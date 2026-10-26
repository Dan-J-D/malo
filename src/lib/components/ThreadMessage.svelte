<script lang="ts">
  import { api, app, qs } from '../api/client';
  import type * as T from '../api/types';
  import { attempt, errorText, notify } from '../state.svelte';
  import { bytes, when, reveal, fileKind, personName } from '../format';
  import { slide } from 'svelte/transition';
  import { ms, ease } from '../motion';
  import { commands, type Command } from '../commands.svelte';
  import { contextMenu, copy, menuUnder, type Entry } from '../menu.svelte';
  import type { Snippet } from 'svelte';
  import Avatar from './Avatar.svelte';
  import Icon from './Icon.svelte';

  // One message of a conversation. Collapsed it is a single line; expanded it loads and shows the
  // message: plain text first, sanitized HTML in a sandboxed frame on request, remote images only
  // when allowed, links opened after confirmation, attachments saved but never opened.
  let {
    m,
    expanded,
    focus = false,
    ontoggle,
    onreply,
    onview,
    composer,
  }: {
    m: T.MessageSummary;
    expanded: boolean;
    /** The message that was opened: it takes the keyboard shortcuts. */
    focus?: boolean;
    ontoggle: () => void;
    onreply: (mode: 'reply' | 'reply-all' | 'forward') => void;
    onview?: (v: T.MessageView) => void;
    /** The reply being written to this message, shown under it. */
    composer?: Snippet;
  } = $props();

  let view = $state<T.MessageView | null>(null);
  let showHtml = $state(false);
  let remote = $state(false);
  let mode: 'message' | 'headers' | 'source' = $state('message');
  let source = $state('');
  let error = $state('');
  let section: HTMLElement | undefined = $state();

  async function load() {
    error = '';
    try {
      view = await api.get<T.MessageView>(`/messages/${m.id}/view${qs({ html: showHtml, remote })}`);
      onview?.(view);
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    if (!expanded) return;
    void showHtml;
    void remote;
    load();
  });

  $effect(() => {
    if (focus && section) section.scrollIntoView({ block: 'nearest', behavior: 'instant' });
  });

  type Link = { n: number; href: string; text: string };
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
    for (const x of view.text.matchAll(/\bhttps?:\/\/[^\s<>"')\]]+/g)) found.add(x[0]);
    return [...found].map((href, i) => ({ n: i + 1, href, text: '' }));
  });
  const links = $derived([...prepared.links, ...textLinks]);

  async function openLink(l: Link) {
    let host = l.href;
    try { host = new URL(l.href).host; } catch { /* mailto etc. */ }
    if (!confirm(`Open this link in your browser?\n\n${l.href}\n\nHost: ${host}`)) return;
    await attempt(() => app.openExternal(l.href));
  }

  async function save(a: T.AttachmentInfo) {
    if (a.warnings.length && !confirm(`Warning:\n- ${a.warnings.join('\n- ')}\n\nSave "${a.filename}" anyway? Malo never opens attachments.`)) return;
    const p = await attempt(() => app.saveAttachment(m.id, a.index, a.filename));
    if (p) notify(`Saved to ${p}`, 'success');
  }

  async function showSource() {
    mode = 'source';
    if (!source) source = (await attempt(() => app.rawSource(m.id))) ?? '';
  }
  const saveRaw = () => attempt(() => app.saveRaw(m.id));

  const sender = $derived(reveal(m.envelope.from_name || m.envelope.from) || '(unknown sender)');
  const recipients = $derived((view ? [...view.to, ...view.cc] : m.envelope.to).map((r) => reveal(personName(r))).join(', '));
  const many = $derived((view ? view.to.length + view.cc.length : m.envelope.to.length) > 1);

  function menu(): Entry[] {
    return [
      { label: 'Reply', icon: 'reply', keys: focus ? 'r' : undefined, run: () => onreply('reply') },
      { label: 'Reply all', icon: 'reply-all', keys: focus ? 'a' : undefined, run: () => onreply('reply-all') },
      { label: 'Forward', icon: 'forward', keys: focus ? 'f' : undefined, run: () => onreply('forward') },
      '-',
      expanded && mode !== 'message' && { label: 'Show message', icon: 'mail-open', run: () => (mode = 'message') },
      expanded && mode !== 'headers' && { label: 'Show headers', icon: 'file', run: () => (mode = 'headers') },
      expanded && mode !== 'source' && { label: 'Show source', icon: 'file', run: showSource },
      expanded && view?.has_html && { label: showHtml ? 'Show plain text' : 'Show HTML (sanitized)', icon: 'file', run: () => (showHtml = !showHtml) },
      expanded && showHtml && { label: remote ? 'Block remote images' : 'Load remote images', icon: 'download', run: () => (remote = !remote) },
      '-',
      { label: 'Copy sender address', icon: 'copy', run: () => copy(m.envelope.from, 'Address copied') },
      { label: 'Save .eml…', icon: 'download', run: saveRaw },
    ];
  }

  commands(() => {
    if (!focus || !view) return [];
    return [
      { id: 'tab-message', group: 'Message', label: 'Show message', keys: '1', run: () => (mode = 'message') },
      { id: 'tab-headers', group: 'Message', label: 'Show headers', keys: '2', run: () => (mode = 'headers') },
      { id: 'tab-source', group: 'Message', label: 'Show source', keys: '3', run: showSource },
      { id: 'html', group: 'Message', label: showHtml ? 'Show plain text' : 'Show HTML (sanitized)', keys: 'h', disabled: !view.has_html, run: () => (showHtml = !showHtml) },
      { id: 'remote', group: 'Message', label: remote ? 'Block remote images' : 'Load remote images', keys: 'i', disabled: !showHtml, run: () => (remote = !remote) },
      { id: 'save-eml', group: 'Message', label: 'Save .eml…', keys: 'mod+s', anywhere: true, run: saveRaw },
      ...view.attachments.map((a): Command => ({ id: `att-${a.index}`, group: 'Attachments', label: `Save ${reveal(a.filename)}…`, run: () => save(a) })),
      ...links.map((l): Command => ({ id: `link-${l.n}`, group: 'Links', label: `Open [${l.n}] ${l.href}`, run: () => openLink(l) })),
    ];
  });
</script>

<section bind:this={section} class="border-b border-line last:border-b-0" {@attach contextMenu(menu)}>
  <!-- The header line opens and closes the message. -->
  <!-- No press effect: the whole row shrinking and springing back reads as a bounce. -->
  <button class="flex w-full items-start gap-3 rounded-none bg-transparent px-6 py-4 text-left hover:bg-transparent! active:transform-none!"
    onclick={ontoggle} aria-expanded={expanded}>
    <Avatar name={sender} seed={m.envelope.from} size={36} />
    <span class="min-w-0 flex-1">
      <span class="flex items-baseline gap-3">
        <span class="untrusted min-w-0 flex-1 truncate font-medium {m.reviewed ? '' : 'text-fg'}">{sender}</span>
        <span class="flex-none text-[0.85rem] text-muted tabular-nums">{when(m.envelope.date ?? m.internal_date)}</span>
      </span>
      <span class="untrusted block truncate text-[0.85rem] text-muted">To: {recipients || '—'}</span>
    </span>
  </button>

  <!-- Opens once the message is loaded (a local request: no visible wait), so it slides open to
       its full height in one go instead of to a "Loading…" line that then jumps. -->
  {#if expanded && (view || error)}
    <div class="-mt-2 pb-5 pl-[4.75rem] pr-6" transition:slide={{ duration: ms(240), easing: ease }}>
      {#if error}
        <p class="callout bad my-2">{error}</p>
      {:else if view}
        {#if view.warnings.length}
          <div class="mb-3 flex flex-col gap-2">
            {#each view.warnings as w}
              <div class="flex items-start gap-2 rounded-lg border border-bad/40 bg-bad/8 px-3 py-2 text-[0.9rem]">
                <span class="mt-0.5 text-bad"><Icon name="alert" size={15} /></span><span>{w}</span>
              </div>
            {/each}
          </div>
        {/if}

        {#if mode === 'message'}
          {#if view.has_html}
            <div class="mb-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-[0.85rem] text-muted">
              <label class="check"><input type="checkbox" class="switch" bind:checked={showHtml} /> Show HTML (sanitized)</label>
              {#if showHtml}<label class="check"><input type="checkbox" class="switch" bind:checked={remote} /> Load remote images</label>{/if}
              {#if showHtml && view.remote_blocked > 0 && !remote}<span class="text-faint">{view.remote_blocked} remote image{view.remote_blocked === 1 ? '' : 's'} blocked</span>{/if}
            </div>
          {/if}
          {#if view.html !== null && view.html !== undefined}
            <iframe class="h-[60vh] w-full rounded-lg border border-line bg-white" title="Message from {sender}" sandbox="" srcdoc={prepared.doc} referrerpolicy="no-referrer"></iframe>
          {:else}
            <pre class="m-0 max-w-[72ch] font-sans text-[0.95rem] leading-relaxed whitespace-pre-wrap break-words">{view.text}</pre>
          {/if}
          {#if links.length}
            <details class="mt-3 text-[0.85rem]"><summary>Links ({links.length})</summary>
              <div class="mt-2 flex flex-col gap-1">
                {#each links as l}
                  <div class="flex items-start gap-2 rounded-lg px-2 py-1.5 hover:bg-raised" {@attach contextMenu(() => [
                    { label: 'Open in browser…', icon: 'external', run: () => openLink(l) },
                    { label: 'Copy link', icon: 'copy', run: () => copy(l.href, 'Link copied') },
                  ])}>
                    <span class="text-faint tabular-nums">[{l.n}]</span>
                    <span class="min-w-0 flex-1"><span class="mono">{l.href}</span>{#if l.text}<br /><span class="text-muted">“{l.text}”</span>{/if}</span>
                    <button class="flex-none px-2 py-0.5" onclick={() => openLink(l)}>Open…</button>
                  </div>
                {/each}
              </div>
            </details>
          {/if}
        {:else if mode === 'headers'}
          <table class="text-[0.85rem]">
            <tbody>{#each view.headers as [k, v]}<tr {@attach contextMenu(() => [
              { label: 'Copy value', icon: 'copy', run: () => copy(v, 'Header copied') },
              { label: 'Copy header line', icon: 'copy', run: () => copy(`${k}: ${v}`, 'Header copied') },
            ])}><td class="mono w-44 text-muted">{k}</td><td class="mono">{v}</td></tr>{/each}</tbody>
          </table>
        {:else}
          <pre class="m-0 font-mono text-[0.8rem] whitespace-pre-wrap break-words">{source || 'Loading…'}</pre>
        {/if}

        {#if view.attachments.length}
          <div class="mt-4 flex flex-wrap gap-2">
            {#each view.attachments as a}
              {@const k = fileKind(a.filename, a.sniffed_type ?? a.declared_type)}
              <button class="max-w-full gap-2 border px-2.5 py-1.5 text-[0.9rem] {a.warnings.length ? 'border-bad/40 bg-bad/8' : 'border-transparent'}"
                onclick={() => save(a)} title="Save as… (declared {a.declared_type}, detected {a.sniffed_type ?? 'unknown'})"
                {@attach contextMenu(() => [
                  { label: 'Save as…', icon: 'download', run: () => save(a) },
                  { label: 'Copy file name', icon: 'copy', run: () => copy(a.filename, 'File name copied') },
                ])}>
                <span class={a.warnings.length ? 'text-bad' : k.tone}><Icon name={a.warnings.length ? 'alert' : k.icon} size={15} /></span>
                <span class="untrusted truncate">{reveal(a.filename)}</span>
                <span class="flex-none text-muted">{bytes(a.size)}</span>
              </button>
            {/each}
          </div>
        {/if}

        {#if view.authentication_results.length}
          <details class="mt-3 text-[0.85rem]"><summary>Sender authentication (SPF / DKIM / DMARC)</summary>
            {#each view.authentication_results as r}<div class="mono mt-1 text-muted">{r}</div>{/each}
          </details>
        {/if}

        <div class="mt-4 flex items-center gap-2">
          <button class="px-2.5 py-1 text-[0.9rem]" onclick={() => onreply('reply')}><Icon name="reply" size={14} /> Reply</button>
          {#if many}<button class="px-2.5 py-1 text-[0.9rem]" onclick={() => onreply('reply-all')}><Icon name="reply-all" size={14} /> Reply all</button>{/if}
          <button class="px-2.5 py-1 text-[0.9rem]" onclick={() => onreply('forward')}><Icon name="forward" size={14} /> Forward</button>
          <span class="flex-1"></span>
          <button class="bg-transparent p-1.5 text-muted hover:text-fg" aria-label="More actions" title="More" onclick={(e) => menuUnder(e.currentTarget, menu())}><Icon name="more" size={16} /></button>
        </div>
      {/if}
    </div>
  {/if}

  {#if composer}<div class="pr-6 pb-5 pl-[4.75rem]">{@render composer()}</div>{/if}
</section>
