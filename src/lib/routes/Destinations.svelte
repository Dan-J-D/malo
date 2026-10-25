<script lang="ts">
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { live, attempt, refreshDestinations, errorText } from '../state.svelte';
  import { bytes } from '../format';
  import Modal from '../components/Modal.svelte';
  import KeyValue from '../components/KeyValue.svelte';

  type Field = { key: string; label: string; secret?: boolean; placeholder?: string };
  const schemes: Record<string, { label: string; fields: Field[] }> = {
    fs: { label: 'Local folder / Docker volume', fields: [{ key: 'root', label: 'Folder (relative to your private area, or an admin-allowed mount)', placeholder: 'backups' }] },
    s3: { label: 'Amazon S3 / S3-compatible (RustFS, MinIO, R2, Wasabi…)', fields: [
      { key: 'bucket', label: 'Bucket' }, { key: 'region', label: 'Region', placeholder: 'us-east-1' },
      { key: 'endpoint', label: 'Endpoint (blank for AWS)', placeholder: 'https://s3.example.com' },
      { key: 'access_key_id', label: 'Access key ID' }, { key: 'secret_access_key', label: 'Secret access key', secret: true } ] },
    gcs: { label: 'Google Cloud Storage', fields: [
      { key: 'bucket', label: 'Bucket' }, { key: 'credential', label: 'Service account JSON (base64)', secret: true },
      { key: 'endpoint', label: 'Endpoint (optional)' } ] },
    azblob: { label: 'Azure Blob Storage', fields: [
      { key: 'container', label: 'Container' }, { key: 'endpoint', label: 'Endpoint', placeholder: 'https://<account>.blob.core.windows.net' },
      { key: 'account_name', label: 'Account name' }, { key: 'account_key', label: 'Account key', secret: true } ] },
    webdav: { label: 'WebDAV (Nextcloud…)', fields: [
      { key: 'endpoint', label: 'Endpoint' }, { key: 'username', label: 'Username' }, { key: 'password', label: 'Password', secret: true } ] },
    b2: { label: 'Backblaze B2', fields: [
      { key: 'bucket', label: 'Bucket' }, { key: 'bucket_id', label: 'Bucket ID' },
      { key: 'application_key_id', label: 'Key ID' }, { key: 'application_key', label: 'Application key', secret: true } ] },
    other: { label: 'Other OpenDAL service (generic options)', fields: [] },
  };

  let editing: T.DestinationView | null = $state(null);
  let open = $state(false);
  let kind = $state('fs');
  let customScheme = $state('');
  let form: T.DestinationInput = $state(blank());
  let extra: Record<string, string> = $state({});
  let test: T.DestinationTest | null = $state(null);
  let busy = $state(false);
  let error = $state('');

  function blank(): T.DestinationInput {
    return { revision: null, name: '', scheme: 'fs', options: {}, root: '', encrypt: true, required_for_purge: true, deep_check: { mode: 'full' } };
  }

  function create() {
    editing = null;
    form = blank();
    kind = 'fs';
    extra = {};
    test = null;
    error = '';
    open = true;
  }

  function edit(d: T.DestinationView) {
    editing = d;
    form = { revision: d.revision, name: d.name, scheme: d.scheme, options: { ...d.options }, root: d.root, encrypt: d.encrypt, required_for_purge: d.required_for_purge, deep_check: d.deep_check };
    kind = d.scheme in schemes ? d.scheme : 'other';
    customScheme = d.scheme;
    const known = new Set(schemes[kind].fields.map((f) => f.key));
    extra = Object.fromEntries(Object.entries(d.options).filter(([k]) => !known.has(k)).map(([k, v]) => [k, v ?? ""]));
    test = null;
    error = '';
    open = true;
  }

  function input(): T.DestinationInput {
    const known: Record<string, string> = {};
    for (const f of schemes[kind].fields) {
      const v = form.options[f.key];
      if (v) known[f.key] = v;
    }
    return { ...form, scheme: kind === 'other' ? customScheme : kind, options: { ...known, ...extra } };
  }

  async function runTest() {
    busy = true;
    error = '';
    try {
      test = await api.post<T.DestinationTest>(`/destinations/test${editing ? `?id=${editing.id}` : ''}`, input());
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function save() {
    busy = true;
    const r = await attempt(() => (editing ? api.put(`/destinations/${editing.id}`, input()) : api.post('/destinations', input())), 'Destination saved');
    busy = false;
    if (r) {
      open = false;
    }
    // Saved, or changed on another device meanwhile (409): show the current state either way.
    await refreshDestinations();
  }

  async function remove(d: T.DestinationView) {
    if (!confirm(`Remove "${d.name}" from Malo? Objects already stored there are NOT deleted. Purge policies requiring it are disarmed.`)) return;
    await attempt(() => api.del(`/destinations/${d.id}`), 'Destination removed');
    await refreshDestinations();
  }

  function rebuild(d: T.DestinationView) {
    if (!confirm(`Rebuild the index from the manifests on "${d.name}"? Existing entries are kept; missing ones are imported.`)) return;
    attempt(() => api.post('/jobs', { kind: { type: 'rebuild_index', destination_id: d.id } }), 'Index rebuild queued');
  }

  function rebuildAll() {
    if (!confirm('Rebuild the index from every destination? All mail found anywhere is imported; folders and flags come from the newest copy of each account. Existing entries are kept.')) return;
    attempt(() => api.post('/jobs', { kind: { type: 'rebuild_index_all' } }), 'Index rebuild queued');
  }

  function verify(d: T.DestinationView, deep: boolean) {
    attempt(() => api.post('/jobs', { kind: { type: 'check', scope: { scope: 'destination', destination_id: d.id }, deep } }), 'Check queued');
  }
</script>

<div class="row"><h1 class="grow">Destinations</h1>{#if live.destinations.length > 1}<button onclick={rebuildAll}>Rebuild index from all</button>{/if}<button class="primary" onclick={create}>Add destination</button></div>
<p class="muted">Every message is written to every destination and read back to verify. Encrypted destinations only ever see random-looking names and ciphertext.</p>

<div class="cards">
  {#each live.destinations as d}
    <div class="panel">
      <div class="row"><strong class="grow">{d.name}</strong>
        {#if d.encrypt}<span class="pill ok">encrypted</span>{:else}<span class="pill warn">plain</span>{/if}
        {#if d.health}{#if d.health.ok}<span class="pill ok">healthy</span>{:else}<span class="pill bad">problems</span>{/if}{/if}
      </div>
      <div class="muted small">{d.scheme}{d.options.bucket ? ` · ${d.options.bucket}` : ''}{d.options.root ? ` · ${d.options.root}` : ''}{d.root ? ` · /${d.root}` : ''}</div>
      <div class="small" style="margin: 0.5rem 0">{Number(d.object_count).toLocaleString()} objects · {bytes(d.stored_bytes)}</div>
      <div class="small muted">Required for purge: {d.required_for_purge ? 'yes' : 'no'} · Deep check: {d.deep_check.mode === 'rotating' ? `rotating 1/${d.deep_check.slices}` : d.deep_check.mode}</div>
      <div class="row" style="margin-top: 0.75rem">
        <button onclick={() => edit(d)}>Edit</button>
        <button onclick={() => verify(d, false)}>Verify</button>
        <button onclick={() => verify(d, true)}>Deep verify</button>
        <button onclick={() => rebuild(d)}>Rebuild index</button>
        <button onclick={() => remove(d)}>Remove</button>
      </div>
    </div>
  {:else}
    <p class="muted">No destinations yet.</p>
  {/each}
</div>

{#if open}
  <Modal title={editing ? `Edit ${editing.name}` : 'Add destination'} onclose={() => (open = false)} wide>
    <div class="cards">
      <label>Name <input bind:value={form.name} placeholder="NAS, S3 Frankfurt…" /></label>
      <label>Type
        <select bind:value={kind} disabled={!!editing}>
          {#each Object.entries(schemes) as [k, s]}<option value={k}>{s.label}</option>{/each}
        </select>
      </label>
      {#if kind === 'other'}<label>OpenDAL scheme <input bind:value={customScheme} disabled={!!editing} placeholder="e.g. oss, cos, sftp" /></label>{/if}
      <label>Prefix inside the storage <input bind:value={form.root} disabled={!!editing} placeholder="malo" /></label>
    </div>
    <div class="cards">
      {#each schemes[kind].fields as f}
        <label>{f.label}
          <input type={f.secret ? 'password' : 'text'} value={form.options[f.key] ?? ''} placeholder={f.placeholder ?? ''}
            oninput={(e) => (form.options = { ...form.options, [f.key]: (e.target as HTMLInputElement).value })} autocomplete="off" />
        </label>
      {/each}
    </div>
    <details open={kind === 'other'}><summary>Additional OpenDAL options</summary><KeyValue bind:values={extra} /></details>
    <label class="check"><input type="checkbox" bind:checked={form.encrypt} disabled={!!editing} /> Encrypt backups (recommended; can't be changed later)</label>
    <label class="check"><input type="checkbox" bind:checked={form.required_for_purge} /> Offer as a required destination for purges</label>
    <div class="row">
      <label>Deep check
        <select value={form.deep_check.mode} onchange={(e) => {
          const m = (e.target as HTMLSelectElement).value;
          form.deep_check = m === 'rotating' ? { mode: 'rotating', slices: 7 } : m === 'off' ? { mode: 'off' } : { mode: 'full' };
        }}>
          <option value="full">Re-hash everything</option>
          <option value="rotating">Rotating slice (saves egress)</option>
          <option value="off">Never download (metadata only)</option>
        </select>
      </label>
      {#if form.deep_check.mode === 'rotating'}
        <label>Slices <input type="number" min="2" value={form.deep_check.slices} oninput={(e) => (form.deep_check = { mode: 'rotating', slices: Number((e.target as HTMLInputElement).value) || 7 })} /></label>
      {/if}
    </div>
    {#if !form.encrypt}<p class="callout">Plain destinations store readable .eml files with mailbox names visible. Anyone with access to the storage can read your mail.</p>{/if}
    {#if error}<p class="callout bad">{error}</p>{/if}
    {#if test}<p class="callout" class:ok={test.ok} class:bad={!test.ok}>{test.ok ? `Write/read/delete OK (${test.write_ms} ms / ${test.read_ms} ms)` : test.error}</p>{/if}
    <div class="row"><button onclick={runTest} disabled={busy}>Test</button><button class="primary" onclick={save} disabled={busy || !form.name}>Save</button></div>
  </Modal>
{/if}
