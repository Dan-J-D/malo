<script lang="ts">
  import { api, app, qs } from '../api/client';
  import type * as T from '../api/types';
  import { attempt, errorText, notify, live } from '../state.svelte';
  import type { Snippet } from 'svelte';
  import { bytes, when, reveal } from '../format';
  import { fly } from 'svelte/transition';
  import { ms, ease } from '../motion';
  import Avatar from './Avatar.svelte';
  import Icon from './Icon.svelte';

  // `toolbar` holds the caller's navigation controls (close, previous, next).
  let { id, toolbar }: { id: number; toolbar?: Snippet } = $props();

  let view: T.MessageView | null = $state(null);
  let showHtml = $state(false);
  let remote = $state(false);
  let tab: 'message' | 'headers' | 'source' = $state('message');
  let source = $state('');
  let error = $state('');

  async function load() {
    error = '';
    try {
      view = await api.get<T.MessageView>(`/messages/${id}/view${qs({ html: showHtml, remote })}`);
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    void id;
    void showHtml;
    void remote;
    load();
  });
  // Opening a message marks it reviewed ("new since last visit" is tracked by Malo, never via server flags).
  $effect(() => {
    const mid = id;
    api.post('/messages/reviewed', { ids: [mid], all: false, account_id: null }).catch(() => undefined);
    const nf = live.newlyFound.find((m) => m.id === mid);
    if (nf) nf.reviewed = true;
  });

  $effect(() => {
    void id;
    showHtml = false;
    remote = false;
    tab = 'message';
    source = '';
  });

  // Links are shown with their real target and only opened after confirmation.
  type Link = { n: number; href: string; text: string };
  const tabs = [['message', 'Message'], ['headers', 'Headers'], ['source', 'Source']] as const;
  let scroller: HTMLElement | undefined = $state();
  // A newly opened message starts at its top, without a smooth scroll back up from the last one.
  $effect(() => {
    void id;
    scroller?.scrollTo({ top: 0, behavior: 'instant' });
  });
  const prepared = $derived.by(() => {
    if (!view?.html) return { doc: '', links: [] as Link[] };
    // DOMParser documents are inert: no scripts run, no resources load.
    const doc = new DOMParser().parseFromString(view.html, 'text/html');
    const links: Link[] = [];
    doc.querySelectorAll('a[href]').forEach((a) => {
      const href = a.getAttribute('href') ?? '';
      const n = links.length + 1;
      links.push({ n, href, text: (a.textContent ?? '').trim().slice(0, 120) });
      a.removeAttribute('href');
      a.setAttribute('title', href);
      a.setAttribute('style', 'color:#2563eb;text-decoration:underline');
      const sup = doc.createElement('sup');
      sup.textContent = `[${n}]`;
      a.after(sup);
    });
    const csp = `default-src 'none'; img-src data:${remote ? ' https:' : ''}; style-src 'unsafe-inline'; font-src data:`;
    // Built as an element, not written as a literal tag: a style tag inside <script> text is picked up
    // as the component's stylesheet by the dev server (and then fails in Tailwind).
    const style = doc.createElement('style');
    style.textContent = 'body{font-family:system-ui,sans-serif;font-size:14px;margin:12px;word-wrap:break-word}img{max-width:100%;height:auto}';
    const head = `<meta http-equiv="Content-Security-Policy" content="${csp}"><meta name="referrer" content="no-referrer"><base target="_self">${style.outerHTML}`;
    return { doc: `<!doctype html><html><head>${head}</head><body>${doc.body.innerHTML}</body></html>`, links };
  });

  const textLinks = $derived.by(() => {
    if (!view || view.html) return [] as Link[];
    const found = new Set<string>();
    for (const m of view.text.matchAll(/\bhttps?:\/\/[^\s<>"')\]]+/g)) found.add(m[0]);
    return [...found].map((href, i) => ({ n: i + 1, href, text: '' }));
  });

  async function openLink(l: Link) {
    let host = l.href;
    try { host = new URL(l.href).host; } catch { /* mailto etc. */ }
    if (!confirm(`Open this link in your browser?\n\n${l.href}\n\nHost: ${host}`)) return;
    await attempt(() => app.openExternal(l.href));
  }

  async function save(a: T.AttachmentInfo) {
    if (a.warnings.length && !confirm(`Warning:\n- ${a.warnings.join('\n- ')}\n\nSave "${a.filename}" anyway? Malo never opens attachments.`)) return;
    const p = await attempt(() => app.saveAttachment(id, a.index, a.filename));
    if (p) notify(`Saved to ${p}`, 'success');
  }

  async function showSource() {
    tab = 'source';
    if (!source) source = (await attempt(() => app.rawSource(id))) ?? '';
  }
</script>

<div class="flex h-12 flex-none items-center gap-1 border-b border-line px-3">
  {@render toolbar?.()}
  <span class="flex-1"></span>
  {#if view}
    <!-- Equal-width tabs, so one indicator can slide between them. -->
    <div class="relative grid grid-cols-3 rounded-lg bg-raised p-0.5 text-[0.85rem]" role="tablist" aria-label="Message view">
      <span aria-hidden="true" class="absolute top-0.5 bottom-0.5 left-0.5 w-[calc((100%-4px)/3)] rounded-md bg-panel shadow-sm dark:bg-white/10 transition-transform duration-300 ease-[cubic-bezier(0.22,1,0.36,1)]"
        style="transform: translateX({tabs.findIndex(([k]) => k === tab) * 100}%)"></span>
      {#each tabs as [key, label]}
        <button role="tab" aria-selected={tab === key} class="relative w-[4.75rem] justify-center rounded-md bg-transparent! px-2.5 py-1 {tab === key ? 'text-fg' : 'text-muted hover:text-fg'}"
          onclick={() => (key === 'source' ? showSource() : (tab = key as typeof tab))}>{label}</button>
      {/each}
    </div>
    <button class="ml-1 border border-line bg-transparent px-2.5 py-1 text-[0.85rem]" onclick={() => attempt(() => app.saveRaw(id))} title="Save the original message, byte for byte">
      <Icon name="download" size={14} /> Save .eml…
    </button>
  {/if}
</div>

<div bind:this={scroller} class="min-h-0 flex-1 overflow-y-auto">
  {#if error}
    <p class="callout bad m-6">{error}</p>
  {:else if !view}
    <p class="m-6 text-muted">Loading…</p>
  {:else}
    {#key view.id}
    <article class="flex flex-col" in:fly={{ y: 8, duration: ms(240), easing: ease }}>
      <header class="px-6 pt-5 pb-4">
        <h2 class="subject m-0 text-lg font-medium leading-snug">{reveal(view.subject) || '(no subject)'}</h2>
        <div class="mt-1.5 flex items-center gap-1.5 text-[0.85rem] text-muted"><Icon name="calendar" size={14} /> {when(view.date)}</div>
      </header>

      {#if view.warnings.length}
        <div class="flex flex-col gap-2 px-6 pb-4">
          {#each view.warnings as w}
            <div class="flex items-start gap-2 rounded-lg border border-bad/40 bg-bad/8 px-3 py-2 text-[0.9rem]">
              <span class="mt-0.5 text-bad"><Icon name="alert" size={15} /></span><span>{w}</span>
            </div>
          {/each}
        </div>
      {/if}

      {#if view.attachments.length}
        <section class="px-6 pb-4">
          <div class="mb-2 text-[0.9rem] text-muted">Attachments <span class="text-faint">[{view.attachments.length}]</span></div>
          <div class="flex flex-wrap gap-2">
            {#each view.attachments as a}
              <div class="flex max-w-full items-center gap-2 rounded-lg border px-2.5 py-1.5 text-[0.9rem] {a.warnings.length ? 'border-bad/40 bg-bad/8' : 'border-line bg-raised'}"
                title="Declared {a.declared_type} · detected {a.sniffed_type ?? 'unknown'}">
                <span class={a.warnings.length ? 'text-bad' : 'text-info'}><Icon name={a.warnings.length ? 'alert' : 'file'} size={15} /></span>
                <span class="untrusted truncate">{reveal(a.filename)}</span>
                <span class="flex-none text-muted">{bytes(a.size)}</span>
                {#if a.sniffed_type && a.sniffed_type !== a.declared_type}<span class="flex-none text-[0.8rem] text-warn">is {a.sniffed_type}</span>{/if}
                <button class="ml-1 flex-none bg-transparent px-1.5 py-0.5 text-[0.85rem] text-accent-2" onclick={() => save(a)}>Save as…</button>
              </div>
              {#each a.warnings as w}<span class="pill bad self-center">{w}</span>{/each}
            {/each}
          </div>
          <p class="mt-2 mb-0 text-[0.8rem] text-faint">Malo never opens attachments. Saved files keep their original bytes.</p>
        </section>
      {/if}

      <div class="border-t border-line px-6 py-4">
        <div class="flex items-start gap-3">
          <Avatar name={reveal(view.from_name || view.from) || '?'} seed={view.from} size={38} />
          <div class="min-w-0 flex-1 text-[0.9rem]">
            <div class="untrusted"><span class="font-medium">{reveal(view.from_name || view.from)}</span>
              {#if view.from_name}<span class="text-muted"> &lt;{reveal(view.from)}&gt;</span>{/if}</div>
            <div class="untrusted text-muted">To: {view.to.join(', ')}</div>
            {#if view.cc.length}<div class="untrusted text-muted">Cc: {view.cc.join(', ')}</div>{/if}
          </div>
        </div>
        {#if view.authentication_results.length}
          <details class="mt-2 ml-[50px] text-[0.85rem]"><summary>Sender authentication (SPF / DKIM / DMARC)</summary>
            {#each view.authentication_results as r}<div class="mono mt-1 text-muted">{r}</div>{/each}
          </details>
        {/if}
      </div>

      <div class="px-6 pb-8">
        {#if tab === 'message'}
          {#if view.has_html}
            <div class="mb-3 flex flex-wrap items-center gap-x-5 gap-y-2 rounded-lg bg-raised px-3 py-2 text-[0.85rem]">
              <label class="check"><input type="checkbox" bind:checked={showHtml} /> Show HTML (sanitized)</label>
              {#if showHtml}
                <label class="check"><input type="checkbox" bind:checked={remote} /> Load remote images for this message</label>
              {/if}
              {#if showHtml && view.remote_blocked > 0 && !remote}<span class="text-muted">{view.remote_blocked} remote image(s) blocked to prevent tracking.</span>{/if}
            </div>
          {/if}
          {#if view.html !== null && view.html !== undefined}
            <iframe class="h-[65vh] w-full rounded-lg border border-line bg-white" title="Message content" sandbox="" srcdoc={prepared.doc} referrerpolicy="no-referrer"></iframe>
            {#if prepared.links.length}
              {@render linkList(`Links in this message (${prepared.links.length})`, prepared.links)}
            {/if}
          {:else}
            <pre class="m-0 font-sans text-[0.95rem] leading-relaxed whitespace-pre-wrap break-words">{view.text}</pre>
            {#if textLinks.length}
              {@render linkList(`Links (${textLinks.length})`, textLinks)}
            {/if}
          {/if}
        {:else if tab === 'headers'}
          <table class="text-[0.85rem]">
            <tbody>{#each view.headers as [k, v]}<tr><td class="mono w-48 text-muted">{k}</td><td class="mono">{v}</td></tr>{/each}</tbody>
          </table>
        {:else}
          <pre class="m-0 font-mono text-[0.8rem] whitespace-pre-wrap break-words">{source || 'Loading…'}</pre>
        {/if}
      </div>
    </article>
    {/key}
  {/if}
</div>

{#snippet linkList(label: string, links: Link[])}
  <details class="mt-4 text-[0.85rem]"><summary>{label}</summary>
    <div class="mt-2 flex flex-col gap-1">
      {#each links as l}
        <div class="flex items-start gap-2 rounded-lg px-2 py-1.5 hover:bg-raised">
          <span class="text-faint tabular-nums">[{l.n}]</span>
          <span class="min-w-0 flex-1"><span class="mono">{l.href}</span>{#if l.text}<br /><span class="text-muted">“{l.text}”</span>{/if}</span>
          <button class="flex-none px-2 py-0.5" onclick={() => openLink(l)}>Open…</button>
        </div>
      {/each}
    </div>
  </details>
{/snippet}
