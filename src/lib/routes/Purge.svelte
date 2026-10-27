<script lang="ts">
  import { ask } from '../confirm.svelte';
  import Select from '../components/Select.svelte';
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { live, route, attempt, refreshAccounts, destName, notify } from '../state.svelte';
  import { commands } from '../commands.svelte';
  import { bytes, when } from '../format';
  import Modal from '../components/Modal.svelte';

  let accountId = $state('');
  const account = $derived(live.accounts.find((a) => a.id === accountId) ?? null);
  let policy: T.PurgePolicy | null = $state(null);
  let boxes: T.MailboxInfo[] = $state([]);
  let preview: T.PurgePreview | null = $state(null);
  let dryRunJob: string | null = $state(null);
  let audit: T.AuditEntry[] = $state([]);
  let arming = $state(false);
  let confirmName = $state('');

  // `#/purge?account=…` (from an account's menu) opens that account's policy.
  $effect(() => {
    const want = new URLSearchParams(route.path.split('?')[1] ?? '').get('account');
    if (want && live.accounts.some((a) => a.id === want)) accountId = want;
    else if (!accountId && live.accounts.length) accountId = live.accounts.find((a) => !a.imported)?.id ?? '';
  });

  commands(() => [
    { id: 'purge-save', group: 'Purge', label: 'Save policy', keys: 'mod+s', anywhere: true, disabled: !dirty || arming, run: save },
    { id: 'purge-dry', group: 'Purge', label: 'Run dry run', keys: 'd', disabled: dirty || !!dryRunJob || !account, run: dryRun },
    { id: 'purge-disarm', group: 'Purge', label: 'Disarm purge', disabled: !account?.policy.armed, run: disarm },
    { id: 'purge-arm', group: 'Purge', label: 'Arm purge…', disabled: !preview || !!preview.blocked_reason || !!account?.policy.armed, run: () => (arming = true) },
    { id: 'purge-arm-confirm', group: 'Purge', label: 'Arm', keys: 'mod+enter', anywhere: true, disabled: !arming || confirmName !== account?.name, run: arm },
    ...live.accounts.filter((a) => !a.imported).map((a) => ({ id: `purge-acc-${a.id}`, group: 'Purge', label: `Purge policy of ${a.name}`, disabled: a.id === accountId, run: () => (accountId = a.id) })),
  ]);

  $effect(() => {
    if (!account) return;
    policy = structuredClone($state.snapshot(account.policy));
    preview = null;
    attempt(() => api.get<T.MailboxInfo[]>(`/mailboxes?account=${account.id}`)).then((b) => (boxes = b ?? []));
    attempt(() => api.get<T.AuditEntry[]>(`/audit?account=${account.id}&limit=300`)).then(
      (a) => (audit = (a ?? []).filter((e) => e.kind.startsWith('purge') || e.kind.startsWith('policy'))),
    );
  });

  // Pick up the dry-run result when its job finishes.
  $effect(() => {
    if (!dryRunJob) return;
    const j = live.jobs.find((x) => x.id === dryRunJob);
    if (j && j.state === 'done') {
      preview = j.result as T.PurgePreview;
      dryRunJob = null;
    } else if (j && (j.state === 'failed' || j.state === 'cancelled')) {
      notify(`Dry run failed: ${j.error}`, 'error');
      dryRunJob = null;
    }
  });

  const dirty = $derived.by(() => {
    const p = policy as T.PurgePolicy | null;
    if (!account || !p) return false;
    return JSON.stringify({ ...p, armed: false, armed_at: null }) !== JSON.stringify({ ...account.policy, armed: false, armed_at: null });
  });

  async function save() {
    if (!policy || !account) return;
    if (account.policy.armed && !(await ask({ title: 'Disarm scheduled purges?', body: 'Changing the policy disarms scheduled purges until you arm them again.', confirm: 'Save and disarm' }))) return;
    // The revision makes a save from a stale page fail instead of overwriting another device's change.
    await attempt(() => api.put(`/accounts/${account!.id}/policy?revision=${account!.revision}`, policy), 'Policy saved (disarmed)');
    await refreshAccounts();
    preview = null;
  }

  async function dryRun() {
    if (!account) return;
    const j = await attempt(() => api.post<T.JobInfo>('/jobs', { kind: { type: 'purge_dry_run', account_id: account.id } }));
    if (j) {
      dryRunJob = j.id;
      if (!live.jobs.some((x) => x.id === j.id)) live.jobs.unshift(j);
    }
  }

  async function arm() {
    if (!account) return;
    const r = await attempt(() => api.post(`/accounts/${account.id}/policy/arm`, { confirm_name: confirmName }), 'Purge armed');
    if (r) {
      arming = false;
      confirmName = '';
      await refreshAccounts();
    }
  }

  async function disarm() {
    if (!account) return;
    await attempt(() => api.post(`/accounts/${account.id}/policy/disarm`), 'Purge disarmed');
    await refreshAccounts();
  }

  async function runNow() {
    if (!account || !preview) return;
    if (!(await ask({
      title: `Delete about ${preview.total_count} messages now?`,
      body: `${bytes(preview.total_bytes)} are permanently deleted from ${account.name} on the mail server.`,
      confirm: 'Purge now',
      danger: true,
    }))) return;
    await attempt(() => api.post('/jobs', { kind: { type: 'purge', account_id: account.id } }), 'Purge started');
  }

  function toggle(list: string[], v: string) {
    const i = list.indexOf(v);
    if (i >= 0) list.splice(i, 1);
    else list.push(v);
  }
</script>

<h1>Purge</h1>
<p class="muted">Malo can permanently delete mail from the server once it is verified in every required destination. Nothing is deleted until you run a dry run and arm the policy by typing the account name. Any later change disarms it.</p>

<div class="panel row">
  <label>Account
    <Select bind:value={accountId} options={live.accounts.filter((a) => !a.imported).map((a) => ({ value: a.id, label: a.name }))} />
  </label>
  {#if account}
    {#if account.policy.armed}
      <span class="pill warn">armed since {when(account.policy.armed_at)}</span>
      {#if account.next_purge}<span class="muted small">next run {when(account.next_purge)}</span>{/if}
      <button onclick={disarm}>Disarm</button>
    {:else}<span class="pill muted">not armed</span>{/if}
    {#if account.purge_blocked}<span class="pill bad" title={account.purge_blocked}>blocked: {account.purge_blocked}</span>{/if}
  {/if}
</div>

{#if account && policy}
  <div class="panel">
    <h2>Retention rule</h2>
    <label>Delete from the server when older than (days) — 0 means everything that is verified
      <input type="number" min="0" bind:value={policy.older_than_days} />
    </label>
    <h3>Must be verified in</h3>
    {#each live.destinations as d}
      <label class="check"><input type="checkbox" checked={policy.required_destinations.includes(d.id)} onchange={() => toggle(policy!.required_destinations, d.id)} />
        {d.name} {d.encrypt ? '' : '(plain)'} {#if !d.required_for_purge}<span class="muted small">— not marked as a purge destination</span>{/if}</label>
    {/each}
    {#if policy.required_destinations.length < 2}<p class="callout small">With fewer than two required destinations, a single storage failure could lose mail that is no longer on the server.</p>{/if}
    <h3>Never delete</h3>
    <label class="check"><input type="checkbox" class="switch" bind:checked={policy.exclude_flagged} /> Flagged (starred) messages</label>
    <details><summary>Excluded mailboxes ({policy.exclude_mailboxes.length})</summary>
      {#each boxes as b}
        <label class="check"><input type="checkbox" checked={policy.exclude_mailboxes.includes(b.name)} onchange={() => toggle(policy!.exclude_mailboxes, b.name)} /> {b.display_name}</label>
      {/each}
    </details>
    <label>Run automatically every (hours, 0 = manual only) <input type="number" min="0" bind:value={policy.schedule_hours} /></label>
    <div class="row"><button class="primary" disabled={!dirty} onclick={save}>Save policy</button>{#if dirty}<span class="muted small">Unsaved changes</span>{/if}</div>
  </div>

  <div class="panel">
    <h2>Dry run</h2>
    <p class="muted small">Counts what would be deleted right now. Required before arming.</p>
    <button disabled={dirty || !!dryRunJob} onclick={dryRun}>{dryRunJob ? 'Running…' : 'Run dry run'}</button>
    {#if preview}
      <p><strong>{preview.total_count.toLocaleString()}</strong> messages · {bytes(preview.total_bytes)} would be permanently deleted.</p>
      {#if preview.blocked_reason}<p class="callout bad">Blocked: {preview.blocked_reason}</p>{/if}
      {#each preview.warnings as w}<p class="callout small">{w}</p>{/each}
      <table class="small"><thead><tr><th>Mailbox</th><th class="right">Messages</th><th class="right">Size</th></tr></thead>
        <tbody>{#each preview.mailboxes as m}<tr><td>{m.mailbox}</td><td class="right">{m.count}</td><td class="right">{bytes(m.bytes)}</td></tr>{/each}</tbody></table>
      <div class="row" style="margin-top: 0.75rem">
        {#if !account.policy.armed}<button class="danger" disabled={!!preview.blocked_reason} onclick={() => (arming = true)}>Arm purge…</button>
        {:else}<button class="danger" disabled={!!preview.blocked_reason || preview.total_count === 0} onclick={runNow}>Purge now</button>{/if}
      </div>
      <p class="muted small">Note: Exchange/Microsoft 365 may keep deleted items in “Recoverable Items” for a while; Malo cannot control that.</p>
    {/if}
  </div>

  <div class="panel">
    <h2>History</h2>
    <table class="small">
      <thead><tr><th>When</th><th>Event</th><th>Details</th></tr></thead>
      <tbody>
        {#each audit as e (e.id)}
          <tr><td>{when(e.at)}</td><td>{e.kind.replace('_', ' ')}</td>
            <td class="mono">{e.kind === 'purged' || e.kind === 'purge_pending' ? `${e.detail.mailbox} · ${e.detail.subject ?? ''} · ${bytes(e.detail.size)}` : e.kind === 'purge_run' ? `${e.detail.deleted} deleted, ${e.detail.skipped} skipped${e.detail.errors?.length ? `, ${e.detail.errors.length} errors` : ''}` : ''}</td></tr>
        {:else}<tr><td colspan="3" class="muted">Nothing yet.</td></tr>{/each}
      </tbody>
    </table>
  </div>
{/if}

{#if arming && account}
  <Modal title="Arm permanent deletion" onclose={() => (arming = false)}>
    <p>After arming, Malo will <strong>permanently delete</strong> messages older than {account.policy.older_than_days} days from <strong>{account.host}</strong>
      {account.policy.schedule_hours > 0 ? `every ${account.policy.schedule_hours} hours` : 'when you run it'}, once each is verified in:
      {account.policy.required_destinations.map(destName).join(', ')}.</p>
    <label>Type the account name <code>{account.name}</code> to confirm <input bind:value={confirmName} /></label>
    <button class="danger" disabled={confirmName !== account.name} onclick={arm}>Arm</button>
  </Modal>
{/if}
