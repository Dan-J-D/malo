<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { live, attempt, accountName, refreshDestinations } from '../state.svelte';
  import { bytes } from '../format';
  import Segmented from '../components/Segmented.svelte';
  import Select from '../components/Select.svelte';
  import { commands } from '../commands.svelte';

  // What each account takes up on each destination, how that grew, and what it costs where a
  // price per GB is known. Sizes are what the destination stores (after compression and
  // encryption, a message kept by several accounts counted for each).

  /** List prices of standard storage, USD per GB-month (decimal GB, as providers bill). */
  const PRESETS: { id: string; label: string; price: number }[] = [
    { id: 's3', label: 'Amazon S3 Standard', price: 0.023 },
    { id: 'gcs', label: 'Google Cloud Storage Standard', price: 0.02 },
    { id: 'azure', label: 'Azure Blob Hot (LRS)', price: 0.018 },
    { id: 'r2', label: 'Cloudflare R2', price: 0.015 },
    { id: 'wasabi', label: 'Wasabi', price: 0.0069 },
    { id: 'b2', label: 'Backblaze B2', price: 0.006 },
  ];
  const GB = 1e9;
  const DAY = 86_400_000;

  let report = $state<T.UsageReport | null>(null);
  let range = $state<"30d" | "1y" | "all">("1y");
  let view = $state<"chart" | "table">("chart");

  async function load() {
    report = (await attempt(() => api.get<T.UsageReport>('/usage'))) ?? null;
  }
  onMount(load);

  commands(() => [{ id: 'storage-refresh', group: 'Storage', label: 'Refresh storage usage', run: load }]);

  // Colour follows the destination, by its place in the full list: filtering never repaints one.
  const SLOTS = 8;
  const slot = (id: string) => {
    const i = live.destinations.findIndex((d) => d.id === id);
    return i < 0 || i >= SLOTS ? 0 : i + 1;
  };

  const cells = $derived(report?.cells ?? []);
  const byDest = $derived.by(() => {
    const m = new Map<string, { messages: number; message_bytes: number; stored: number }>();
    for (const c of cells) {
      const e = m.get(c.destination_id) ?? { messages: 0, message_bytes: 0, stored: 0 };
      e.messages += Number(c.messages);
      e.message_bytes += Number(c.message_bytes);
      e.stored += Number(c.stored_bytes);
      m.set(c.destination_id, e);
    }
    return m;
  });
  const accounts = $derived([...new Set(cells.map((c) => c.account_id))].sort((a, b) => accountName(a).localeCompare(accountName(b))));
  const dests = $derived(live.destinations.filter((d) => byDest.has(d.id) || d.features.price_per_gb_month != null));
  const cell = (a: string, d: string) => cells.find((c) => c.account_id === a && c.destination_id === d);

  /** Daily totals per destination, filled forward to today. */
  const series = $derived.by(() => {
    const hist = report?.history ?? [];
    if (!hist.length) return { days: [] as number[], values: new Map<string, number[]>() };
    const today = Math.floor(Date.now() / DAY) * DAY;
    const first = Date.parse(hist[0].date);
    const days: number[] = [];
    for (let t = first; t <= today; t += DAY) days.push(t);
    const values = new Map<string, number[]>();
    for (const id of new Set(hist.map((p) => p.destination_id))) {
      const at = new Map(hist.filter((p) => p.destination_id === id).map((p) => [Date.parse(p.date), Number(p.stored_bytes)]));
      let last = 0;
      values.set(id, days.map((t) => (last = at.get(t) ?? last)));
    }
    return { days, values };
  });

  /** What a destination grew by over the last 30 days (bytes). */
  function growth30(id: string): number {
    const v = series.values.get(id);
    if (!v?.length) return 0;
    return v[v.length - 1] - (v[v.length - 31] ?? 0);
  }

  const price = (d: T.DestinationView) => d.features.price_per_gb_month ?? null;
  const money = (n: number) => n.toLocaleString(undefined, { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: n < 1 ? 3 : 2 });

  const totals = $derived.by(() => {
    let stored = 0, message = 0, cost = 0, costYear = 0, priced = 0;
    for (const d of dests) {
      const e = byDest.get(d.id);
      stored += e?.stored ?? 0;
      if (d.encrypt) message += e?.message_bytes ?? 0;
      const p = price(d);
      if (p != null) {
        priced++;
        cost += ((e?.stored ?? 0) / GB) * p;
        costYear += (((e?.stored ?? 0) + 12 * Math.max(0, growth30(d.id))) / GB) * p;
      }
    }
    const encStored = dests.filter((d) => d.encrypt).reduce((n, d) => n + (byDest.get(d.id)?.stored ?? 0), 0);
    return { stored, cost, costYear, priced, saved: message > 0 ? 1 - encStored / message : 0 };
  });

  async function savePrice(d: T.DestinationView, p: number | null) {
    if (p != null && (!Number.isFinite(p) || p < 0)) return;
    const input: T.DestinationInput = {
      revision: d.revision, name: d.name, scheme: d.scheme, options: d.options, root: d.root, encrypt: d.encrypt,
      required_for_purge: d.required_for_purge, deep_check: d.deep_check, recovery_secrets: d.recovery_secrets ?? false,
      features: { ...d.features, price_per_gb_month: p ?? undefined },
    };
    await attempt(() => api.put(`/destinations/${d.id}`, input), 'Price saved');
    await refreshDestinations();
  }

  // ── Chart ──
  let width = $state(640);
  const H = 240;
  const M = { top: 12, bottom: 26, left: 64 };
  const shown = $derived(live.destinations.filter((d) => series.values.has(d.id)));
  const labelled = $derived(shown.length <= 4);
  const right = $derived(labelled ? 120 : 12);
  const from = $derived.by(() => {
    const n = series.days.length;
    const keep = range === '30d' ? 31 : range === '1y' ? 366 : n;
    return Math.max(0, n - keep);
  });
  const days = $derived(series.days.slice(from));
  const yMax = $derived(Math.max(1, ...shown.flatMap((d) => series.values.get(d.id)!.slice(from))));

  /** Round steps in the unit that fits the largest value. */
  const ticks = $derived.by(() => {
    const unit = [1, 1024, 1024 ** 2, 1024 ** 3, 1024 ** 4].findLast((u) => yMax >= u) ?? 1;
    const raw = yMax / unit / 4;
    const mag = 10 ** Math.floor(Math.log10(raw));
    const step = ([1, 2, 5, 10].find((s) => s * mag >= raw) ?? 10) * mag * unit;
    const out: number[] = [];
    for (let v = 0; v <= yMax * 1.0001 + step; v += step) {
      out.push(v);
      if (v >= yMax) break;
    }
    return out;
  });
  const top = $derived(ticks[ticks.length - 1] || 1);
  const plotW = $derived(Math.max(80, width - M.left - right));
  const x = (i: number) => M.left + (days.length > 1 ? (i / (days.length - 1)) * plotW : plotW / 2);
  const y = (v: number) => M.top + (1 - v / top) * (H - M.top - M.bottom);

  const xTicks = $derived.by(() => {
    if (days.length < 2) return days.map((_, i) => i);
    const count = Math.max(2, Math.min(6, Math.floor(plotW / 110)));
    return Array.from({ length: count }, (_, k) => Math.round((k / (count - 1)) * (days.length - 1)));
  });
  const dayLabel = (t: number) =>
    new Date(t).toLocaleDateString(undefined, range === '30d' ? { month: 'short', day: 'numeric' } : { month: 'short', year: '2-digit' });

  function path(id: string): string {
    const v = series.values.get(id)!.slice(from);
    return v.map((b, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(b).toFixed(1)}`).join('');
  }

  /** End labels, pushed apart where lines end close together; a leader line joins moved ones. */
  const labels = $derived.by(() => {
    if (!labelled || !days.length) return [];
    const end = days.length - 1;
    const items = shown
      .map((d) => ({ d, at: y(series.values.get(d.id)![from + end]), ly: 0 }))
      .sort((a, b) => a.at - b.at);
    let prev = -Infinity;
    for (const it of items) {
      it.ly = Math.max(it.at, prev + 15);
      prev = it.ly;
    }
    const over = prev - (H - M.bottom);
    if (over > 0) for (const it of items) it.ly -= over;
    return items;
  });

  let hover: number | null = $state(null);
  function move(e: PointerEvent) {
    const r = (e.currentTarget as SVGElement).getBoundingClientRect();
    const px = e.clientX - r.left;
    if (days.length < 2) return void (hover = days.length ? 0 : null);
    const i = Math.round(((px - M.left) / plotW) * (days.length - 1));
    hover = Math.min(days.length - 1, Math.max(0, i));
  }
  const tip = $derived.by(() => {
    if (hover === null || !days[hover]) return null;
    const rows = shown
      .map((d) => ({ d, v: series.values.get(d.id)![from + hover!] }))
      .sort((a, b) => b.v - a.v);
    const left = x(hover) > M.left + plotW / 2;
    return { rows, date: new Date(days[hover]).toLocaleDateString(undefined, { dateStyle: 'medium' }), px: x(hover), left };
  });

  /** Table view: one row per week (or day for the last 30), newest first. */
  const tableRows = $derived.by(() => {
    const step = range === '30d' ? 1 : 7;
    const out: number[] = [];
    for (let i = days.length - 1; i >= 0; i -= step) out.push(i);
    return out;
  });
</script>

<div class="row"><h1 class="grow">Storage</h1><button onclick={load}>Refresh</button></div>
<p class="muted">What your mail takes up on each destination and how it grows. Sizes are as stored: compressed and encrypted where the destination does that.</p>

{#if report}
  <div class="cards">
    <div class="panel"><div class="muted small">Stored on all destinations</div><div class="stat">{bytes(totals.stored)}</div></div>
    <div class="panel">
      <div class="muted small">Estimated cost per month</div>
      {#if totals.priced}
        <div class="stat">{money(totals.cost)}</div>
        <div class="muted small">about {money(totals.costYear)} a month in a year at the current growth</div>
      {:else}
        <div class="stat text-muted">—</div><div class="muted small">Set a price per GB below</div>
      {/if}
    </div>
    {#if totals.saved > 0.01}
      <div class="panel"><div class="muted small">Saved by compression</div><div class="stat">{Math.round(totals.saved * 100)}%</div><div class="muted small">of the size of the messages, on encrypted destinations</div></div>
    {/if}
  </div>

  <div class="panel">
    <div class="row mb-2">
      <h2 class="grow my-0!">Growth</h2>
      <Segmented label="Time range" bind:value={range} options={[{ value: '30d', label: '30 days' }, { value: '1y', label: 'Year' }, { value: 'all', label: 'All' }]} />
      <Segmented label="Show as" bind:value={view} options={[{ value: 'chart', label: 'Chart' }, { value: 'table', label: 'Table' }]} />
    </div>
    <p class="muted small mt-0">What each destination holds now, by the day it was written. Purged mail no longer counts.</p>
    {#if !days.length}
      <p class="muted">Nothing stored yet.</p>
    {:else if view === 'chart'}
      {#if shown.length > 1}
        <ul class="legend">
          {#each shown as d (d.id)}<li><span class="key s{slot(d.id)}"></span>{d.name}</li>{/each}
        </ul>
      {/if}
      <div class="viz" bind:clientWidth={width}>
        <svg {width} height={H} role="img" aria-label="Stored bytes per destination over time"
          onpointermove={move} onpointerleave={() => (hover = null)}>
          {#each ticks as t}
            <line class="grid" x1={M.left} x2={M.left + plotW} y1={y(t)} y2={y(t)} />
            <text class="axis" x={M.left - 8} y={y(t)} dy="0.32em" text-anchor="end">{bytes(t)}</text>
          {/each}
          {#each xTicks as i}
            <text class="axis" x={x(i)} y={H - 6} text-anchor={i === 0 ? 'start' : i === days.length - 1 ? 'end' : 'middle'}>{dayLabel(days[i])}</text>
          {/each}
          {#each shown as d (d.id)}
            <path class="line s{slot(d.id)}" d={path(d.id)} />
          {/each}
          {#each labels as l (l.d.id)}
            {#if Math.abs(l.ly - l.at) > 2}
              <path class="leader" d="M{x(days.length - 1) + 4},{l.at} L{x(days.length - 1) + 12},{l.ly}" />
            {/if}
            <text class="label" x={x(days.length - 1) + 14} y={l.ly} dy="0.32em">{l.d.name}</text>
          {/each}
          {#if tip}
            <line class="cross" x1={tip.px} x2={tip.px} y1={M.top} y2={H - M.bottom} />
            {#each tip.rows as r (r.d.id)}
              <circle class="dot s{slot(r.d.id)}" cx={tip.px} cy={y(r.v)} r="4" />
            {/each}
          {/if}
        </svg>
        {#if tip}
          <div class="tip" style="left: {tip.px}px; transform: translateX({tip.left ? 'calc(-100% - 12px)' : '12px'})">
            <div class="font-medium">{tip.date}</div>
            {#each tip.rows as r (r.d.id)}
              <div class="flex items-center gap-2"><span class="key s{slot(r.d.id)}"></span><span class="grow">{r.d.name}</span><span class="tabular-nums">{bytes(r.v)}</span></div>
            {/each}
          </div>
        {/if}
      </div>
    {:else}
      <div class="max-h-80 overflow-auto">
        <table>
          <thead><tr><th>Date</th>{#each shown as d (d.id)}<th class="text-right">{d.name}</th>{/each}</tr></thead>
          <tbody>
            {#each tableRows as i}
              <tr><td>{new Date(days[i]).toLocaleDateString()}</td>{#each shown as d (d.id)}<td class="text-right tabular-nums">{bytes(series.values.get(d.id)![from + i])}</td>{/each}</tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>

  <div class="panel">
    <h2>Destinations</h2>
    <div class="overflow-x-auto">
      <table>
        <thead><tr><th>Destination</th><th class="text-right">Messages</th><th class="text-right">Stored</th><th class="text-right">Last 30 days</th><th>Price per GB-month</th><th class="text-right">Per month</th></tr></thead>
        <tbody>
          {#each dests as d (d.id)}
            {@const e = byDest.get(d.id)}
            {@const p = price(d)}
            <tr>
              <td><span class="key s{slot(d.id)} mr-2"></span>{d.name}</td>
              <td class="text-right tabular-nums">{(e?.messages ?? 0).toLocaleString()}</td>
              <td class="text-right tabular-nums">{bytes(e?.stored ?? 0)}</td>
              <td class="text-right tabular-nums">{growth30(d.id) > 0 ? `+${bytes(growth30(d.id))}` : '—'}</td>
              <td>
                <div class="flex items-center gap-1.5">
                  <span class="text-muted">$</span>
                  <input class="w-24" type="number" min="0" step="0.001" value={p ?? ''} placeholder="none" aria-label="Price per GB-month for {d.name}"
                    onchange={(ev) => { const v = ev.currentTarget.value; void savePrice(d, v === '' ? null : Number(v)); }} />
                  <Select value="" options={[{ value: '', label: 'Presets' }, ...PRESETS.map((s) => ({ value: s.id, label: s.label, hint: `$${s.price}` }))]}
                    onchange={(id) => { const s = PRESETS.find((x) => x.id === id); if (s) void savePrice(d, s.price); }} />
                </div>
              </td>
              <td class="text-right tabular-nums">{p != null ? money(((e?.stored ?? 0) / GB) * p) : '—'}</td>
            </tr>
          {:else}
            <tr><td colspan="6" class="muted">No destinations yet.</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="muted small">Estimates cover stored data only, at list prices; requests, downloads (deep checks, restores) and minimum storage periods are billed on top by some providers. Objects under Object Lock stay billed until their lock ends.</p>
  </div>

  {#if accounts.length}
    <div class="panel">
      <h2>By account</h2>
      <div class="overflow-x-auto">
        <table>
          <thead><tr><th>Account</th>{#each dests as d (d.id)}<th class="text-right">{d.name}</th>{/each}</tr></thead>
          <tbody>
            {#each accounts as a (a)}
              <tr>
                <td>{accountName(a)}</td>
                {#each dests as d (d.id)}
                  {@const c = cell(a, d.id)}
                  <td class="text-right tabular-nums" title={c ? `${Number(c.messages).toLocaleString()} messages, ${bytes(c.message_bytes)} before compression and encryption` : ''}>{c ? bytes(c.stored_bytes) : '—'}</td>
                {/each}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {/if}
{/if}

<style>
  /* Categorical slots in fixed order (validated: CVD-separated on these surfaces, both modes). */
  .viz, .legend, table {
    --s1: #2a78d6; --s2: #eb6834; --s3: #1baf7a; --s4: #eda100;
    --s5: #e87ba4; --s6: #008300; --s7: #6250d6; --s8: #e34948;
  }
  @media (prefers-color-scheme: dark) {
    .viz, .legend, table {
      --s1: #3987e5; --s2: #d95926; --s3: #199e70; --s4: #c98500;
      --s5: #d55181; --s6: #008300; --s7: #9085e9; --s8: #e66767;
    }
  }
  .s0 { --c: var(--muted); }
  .s1 { --c: var(--s1); } .s2 { --c: var(--s2); } .s3 { --c: var(--s3); } .s4 { --c: var(--s4); }
  .s5 { --c: var(--s5); } .s6 { --c: var(--s6); } .s7 { --c: var(--s7); } .s8 { --c: var(--s8); }

  .viz { position: relative; touch-action: pan-y; }
  svg { display: block; overflow: visible; }
  .grid { stroke: var(--line); stroke-width: 1; }
  .axis { fill: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
  .line { fill: none; stroke: var(--c); stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
  .label { fill: var(--text); font-size: 12px; }
  .leader { stroke: var(--faint); stroke-width: 1; fill: none; }
  .cross { stroke: var(--faint); stroke-width: 1; }
  .dot { fill: var(--c); stroke: var(--sunken); stroke-width: 2; }
  .tip {
    position: absolute; top: 8px; pointer-events: none; min-width: 12rem;
    background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
    padding: 0.45rem 0.6rem; font-size: 0.8rem; box-shadow: 0 6px 20px rgb(0 0 0 / 0.12);
  }
  .legend { display: flex; flex-wrap: wrap; gap: 0.25rem 1rem; list-style: none; margin: 0 0 0.5rem; padding: 0; font-size: 0.8rem; color: var(--muted); }
  .legend li { display: flex; align-items: center; gap: 0.4rem; margin: 0; }
  .key { display: inline-block; width: 12px; height: 3px; border-radius: 2px; background: var(--c); vertical-align: middle; flex: none; }
</style>
