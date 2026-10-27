<script lang="ts">
  import { api, app, qs } from '../api/client';
  import type * as T from '../api/types';
  import { attempt, errorText, notify } from '../state.svelte';
  import { ask } from '../confirm.svelte';
  import { bytes, when, reveal, fileKind, personName, addressOf } from '../format';
  import { slide } from 'svelte/transition';
  import { ms, ease } from '../motion';
  import { commands, type Command } from '../commands.svelte';
  import { contextMenu, copy, menuUnder, type Entry } from '../menu.svelte';
  import type { Snippet } from 'svelte';
  import Avatar from './Avatar.svelte';
  import Icon from './Icon.svelte';
  import Segmented from './Segmented.svelte';
  import { authReport, receivedSpf, verdicts, tone, meaning, type Method } from '../auth';

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
  let authOpen = $state(false);
  let headerFilter = $state('');
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

  /** `shown`: a different site the link's text names, e.g. text "paypal.com" on a link elsewhere. */
  type Link = { n: number; href: string; text: string; shown?: string };

  const hostOf = (s: string) => {
    try { return new URL(s).hostname.toLowerCase().replace(/^www\./, ''); } catch { return ''; }
  };
  /** The site a link's text claims to go to, when that isn't where it goes. */
  function deceptive(text: string, href: string): string | undefined {
    const m = /^\s*(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[\/:?#]\S*)?\s*$/i.exec(text);
    if (!m) return undefined;
    const claimed = m[1].toLowerCase().replace(/^www\./, '');
    const real = hostOf(href);
    if (!real || real === claimed || real.endsWith(`.${claimed}`)) return undefined;
    return claimed;
  }
  const prepared = $derived.by(() => {
    if (!view?.html) return { doc: '', links: [] as Link[] };
    // DOMParser documents are inert: no scripts run, no resources load.
    const doc = new DOMParser().parseFromString(view.html, 'text/html');
    const links: Link[] = [];
    doc.querySelectorAll('a[href]').forEach((a) => {
      const href = a.getAttribute('href') ?? '';
      const n = links.length + 1;
      const text = (a.textContent ?? '').trim().slice(0, 120);
      links.push({ n, href, text, shown: deceptive(text, href) });
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
    style.textContent = 'html{overflow-y:hidden}body{font-family:system-ui,sans-serif;font-size:14px;margin:12px;word-wrap:break-word}img{max-width:100%;height:auto}';
    const head = `<meta http-equiv="Content-Security-Policy" content="${csp}"><meta name="referrer" content="no-referrer"><base target="_self">${style.outerHTML}`;
    return { doc: `<!doctype html><html><head>${head}</head><body>${doc.body.innerHTML}</body></html>`, links };
  });

  /** The frame grows to its content, so a long message scrolls with the page, not inside a box.
   *  Same-origin lets the app measure it; with no allow-scripts nothing in it can run. */
  function fitContent(frame: HTMLIFrameElement) {
    let observer: ResizeObserver | undefined;
    const fit = () => {
      const d = frame.contentDocument;
      if (!d?.documentElement) return;
      // The frame's own border is part of its height (border-box).
      const border = frame.offsetHeight - frame.clientHeight;
      frame.style.height = `${Math.max(80, Math.ceil(d.documentElement.scrollHeight)) + border}px`;
    };
    const loaded = () => {
      observer?.disconnect();
      fit();
      const body = frame.contentDocument?.body;
      if (body) {
        observer = new ResizeObserver(fit);
        observer.observe(body);
      }
    };
    frame.addEventListener('load', loaded);
    if (frame.contentDocument?.readyState === 'complete') loaded();
    return () => {
      frame.removeEventListener('load', loaded);
      observer?.disconnect();
    };
  }

  const textLinks = $derived.by(() => {
    if (!view || view.html) return [] as Link[];
    const found = new Set<string>();
    for (const x of view.text.matchAll(/\bhttps?:\/\/[^\s<>"')\]]+/g)) found.add(x[0]);
    return [...found].map((href, i): Link => ({ n: i + 1, href, text: '' }));
  });
  const links = $derived([...prepared.links, ...textLinks]);

  async function openLink(l: Link) {
    let host = l.href;
    try { host = new URL(l.href).host; } catch { /* mailto etc. */ }
    const ok = await ask({
      title: 'Open this link in your browser?',
      body: l.href,
      mono: true,
      detail: `Goes to ${host}`,
      warning: l.shown ? `The link’s text says ${l.shown}, but it goes to ${host}. This is a common phishing trick.` : undefined,
      confirm: 'Open in browser',
      danger: !!l.shown,
    });
    if (ok) await attempt(() => app.openExternal(l.href));
  }

  async function save(a: T.AttachmentInfo) {
    if (a.warnings.length && !(await ask({
      title: `Save “${a.filename}” anyway?`,
      list: a.warnings,
      detail: 'Malo never opens attachments. Be careful opening it yourself.',
      confirm: 'Save anyway',
      danger: true,
    }))) return;
    const p = await attempt(() => app.saveAttachment(m.id, a.index, a.filename));
    if (p) notify(`Saved to ${p}`, 'success');
  }

  async function showSource() {
    mode = 'source';
    if (!source) source = (await attempt(() => app.rawSource(m.id))) ?? '';
  }
  const saveRaw = () => attempt(() => app.saveRaw(m.id));

  const sender = $derived(reveal(m.envelope.from_name || m.envelope.from) || '(unknown sender)');
  /** The real address, always shown next to a display name: the name alone can say anything. */
  const address = $derived(m.envelope.from_name ? reveal(m.envelope.from) : '');
  /** Replies go somewhere other than the sender (Reply-To). */
  const replyElsewhere = $derived(
    (view?.reply_to ?? []).map(addressOf).filter((a) => a && a !== addressOf(view?.from ?? m.envelope.from)),
  );
  const replyOtherDomain = $derived.by(() => {
    const domain = (a: string) => a.split('@').pop() ?? '';
    const own = domain(addressOf(view?.from ?? m.envelope.from));
    return replyElsewhere.some((a) => domain(a) !== own);
  });
  const suspicious = $derived(links.filter((l) => l.shown).length);
  const auth = $derived(view ? authReport(view.authentication_results) : null);
  const checks = $derived(view ? verdicts(auth, receivedSpf(view.headers)) : null);
  const METHOD_NAMES: [Method, string][] = [['spf', 'SPF'], ['dkim', 'DKIM'], ['dmarc', 'DMARC']];
  const TONE_ICON = { ok: 'check', warn: 'alert', bad: 'x', muted: 'help' } as const;
  /** Headers a reader looks for first; the rest follow in message order. */
  const KEY_HEADERS = ['from', 'sender', 'reply-to', 'to', 'cc', 'subject', 'date', 'return-path', 'message-id'];
  const shownHeaders = $derived.by(() => {
    if (!view) return [];
    const q = headerFilter.trim().toLowerCase();
    return view.headers
      .map(([k, v], i) => ({ k, v, i, key: KEY_HEADERS.indexOf(k.toLowerCase()) }))
      .filter((h) => !q || h.k.toLowerCase().includes(q) || h.v.toLowerCase().includes(q))
      .sort((a, b) => (a.key < 0 ? 99 : a.key) - (b.key < 0 ? 99 : b.key) || a.i - b.i);
  });
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
  <button class="flex w-full items-start gap-3 rounded-none bg-transparent px-4 py-4 text-left md:px-6 hover:bg-transparent! active:transform-none!"
    onclick={ontoggle} aria-expanded={expanded}>
    <Avatar name={sender} seed={m.envelope.from} size={36} />
    <span class="min-w-0 flex-1">
      <span class="flex items-baseline gap-3">
        <span class="min-w-0 flex-1 truncate">
          <span class="untrusted font-medium {m.reviewed ? '' : 'text-fg'}">{sender}</span>
          {#if address}<span class="untrusted ml-1 text-[0.85rem] text-muted">&lt;{address}&gt;</span>{/if}
        </span>
        <span class="flex-none text-[0.85rem] text-muted tabular-nums">{when(m.envelope.date ?? m.internal_date)}</span>
      </span>
      {#if !expanded && m.preview}
        <span class="untrusted block truncate text-[0.85rem] text-muted">{reveal(m.preview)}</span>
      {:else}
        <span class="untrusted block truncate text-[0.85rem] text-muted">To: {recipients || '—'}</span>
      {/if}
    </span>
  </button>

  <!-- Opens once the message is loaded (a local request: no visible wait), so it slides open to
       its full height in one go instead of to a "Loading…" line that then jumps. -->
  {#if expanded && (view || error)}
    <div class="-mt-2 pr-4 pb-5 pl-4 md:pr-6 md:pl-[4.75rem]" transition:slide={{ duration: ms(240), easing: ease }}>
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

        {#if replyElsewhere.length}
          <div class="mb-3 flex items-start gap-2 rounded-lg border px-3 py-2 text-[0.9rem] {replyOtherDomain ? 'border-warn/40 bg-warn/8' : 'border-line'}">
            <span class="mt-0.5 {replyOtherDomain ? 'text-warn' : 'text-muted'}"><Icon name="reply" size={15} /></span>
            <span>Replies go to <span class="untrusted mono">{reveal(replyElsewhere.join(', '))}</span>{replyOtherDomain ? ', not to the sender’s domain.' : '.'}</span>
          </div>
        {/if}

        <div class="mb-4 flex flex-wrap items-center gap-x-4 gap-y-2">
          <Segmented label="Show" class="w-[21.5rem] max-w-full" bind:value={mode} onchange={(v) => v === 'source' && showSource()} options={[
            { value: 'message', label: 'Message', icon: 'mail-open' },
            { value: 'headers', label: 'Headers', icon: 'file', title: `${view.headers.length} headers` },
            { value: 'source', label: 'Source', icon: 'server' },
          ]} />
          <span class="flex-1"></span>
          {#if checks}
            <button class="gap-1.5 border border-line bg-transparent px-2 py-1 text-[0.8rem] {authOpen ? 'bg-raised!' : ''}" aria-expanded={authOpen}
              onclick={() => (authOpen = !authOpen)} title={auth ? `Checked by ${auth.by} when the message arrived` : 'No authentication results in this message'}>
              {#each METHOD_NAMES as [m, name]}
                {@const t = tone(checks[m][0]?.result)}
                <span class="pill {t} gap-1 px-1.5!"><Icon name={TONE_ICON[t]} size={12} />{name}</span>
              {/each}
              <span class="inline-flex text-muted transition-transform {authOpen ? 'rotate-180' : ''}"><Icon name="chevron" size={13} /></span>
            </button>
          {/if}
        </div>

        {#if authOpen && checks}
          <div class="mb-4 overflow-hidden rounded-lg border border-line text-[0.85rem]" transition:slide={{ duration: ms(200), easing: ease }}>
            <div class="flex items-center gap-2 border-b border-line bg-sunken px-3 py-2 text-muted">
              <Icon name="shield" size={14} />
              {#if auth}<span>Checked by <span class="mono text-fg">{auth.by || 'the receiving server'}</span> when the message arrived</span>
              {:else}<span>This message carries no Authentication-Results: the receiving server didn’t record a check</span>{/if}
            </div>
            {#each METHOD_NAMES as [m, name]}
              {@const best = checks[m][0]}
              {@const t = tone(best?.result)}
              <div class="grid grid-cols-[5.25rem_minmax(0,1fr)] gap-x-3 border-b border-line px-3 py-2.5 last:border-b-0">
                <span class="pill {t} self-start justify-self-start"><Icon name={TONE_ICON[t]} size={12} />{name}</span>
                <div class="min-w-0">
                  <div><span class="font-medium">{best ? best.result : 'none'}</span><span class="ml-1.5 text-muted">{meaning(best, m)}</span></div>
                  {#each checks[m] as c}
                    <div class="mt-0.5 truncate text-muted" title={c.comment}>
                      {#if c.domain}<span class="untrusted mono text-fg">{c.domain}</span>{/if}
                      {#if checks[m].length > 1}<span class="pill {tone(c.result)} ml-1 px-1!">{c.result}</span>{/if}
                      {#each c.props.filter(([k]) => k === 'header.s') as [, sel]}<span class="ml-1">selector <span class="mono">{sel}</span></span>{/each}
                      {#if m === 'dmarc' && c.comment}<span class="ml-1">{c.comment}</span>{/if}
                    </div>
                  {/each}
                </div>
              </div>
            {/each}
            {#if auth}
              <details class="border-t border-line px-3 py-2">
                <summary class="cursor-pointer text-muted">Show the header{auth.others ? ` (and ${auth.others} more added on the way)` : ''}</summary>
                {#each view.authentication_results as r, i}<div class="mono mt-1.5 break-all text-[0.8rem] {i === view.authentication_results.indexOf(auth.raw) ? '' : 'text-muted'}">{r}</div>{/each}
              </details>
            {/if}
          </div>
        {/if}

        {#if mode === 'message'}
          {#if view.has_html}
            <div class="mb-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-[0.85rem] text-muted">
              <label class="check"><input type="checkbox" class="switch" bind:checked={showHtml} /> Show HTML (sanitized)</label>
              {#if showHtml}<label class="check"><input type="checkbox" class="switch" bind:checked={remote} /> Load remote images</label>{/if}
              {#if showHtml && view.remote_blocked > 0 && !remote}<span class="text-faint">{view.remote_blocked} remote image{view.remote_blocked === 1 ? '' : 's'} blocked</span>{/if}
              {#if showHtml && prepared.links.length}<span class="text-faint">Links are numbered [1], [2]…: open them from Links below the message</span>{/if}
            </div>
          {/if}
          {#if view.html !== null && view.html !== undefined}
            <iframe class="block h-40 w-full rounded-lg border border-line bg-white" title="Message from {sender}" sandbox="allow-same-origin" srcdoc={prepared.doc} referrerpolicy="no-referrer" scrolling="no" {@attach fitContent}></iframe>
          {:else}
            <pre class="m-0 max-w-[72ch] font-sans text-[0.95rem] leading-relaxed whitespace-pre-wrap break-words">{view.text}</pre>
          {/if}
          {#if links.length}
            <details class="mt-3 text-[0.85rem]" open={suspicious > 0}><summary>Links ({links.length}){#if suspicious}<span class="ml-2 text-bad">{suspicious} {suspicious === 1 ? 'goes' : 'go'} somewhere other than {suspicious === 1 ? 'its' : 'their'} text says</span>{/if}</summary>
              <div class="mt-2 flex flex-col gap-1">
                {#each links as l}
                  <div class="flex items-start gap-2 rounded-lg px-2 py-1.5 hover:bg-raised" {@attach contextMenu(() => [
                    { label: 'Open in browser…', icon: 'external', run: () => openLink(l) },
                    { label: 'Copy link', icon: 'copy', run: () => copy(l.href, 'Link copied') },
                  ])}>
                    <span class="text-faint tabular-nums">[{l.n}]</span>
                    <span class="min-w-0 flex-1"><span class="mono">{l.href}</span>{#if l.text}<br /><span class="untrusted text-muted">“{reveal(l.text)}”</span>{/if}
                      {#if l.shown}<br /><span class="pill bad mt-1"><Icon name="alert" size={12} /> Text says {l.shown}, link goes to {hostOf(l.href)}</span>{/if}</span>
                    <button class="flex-none px-2 py-0.5" onclick={() => openLink(l)}>Open…</button>
                  </div>
                {/each}
              </div>
            </details>
          {/if}
        {:else if mode === 'headers'}
          <div class="mb-2 flex items-center gap-2">
            <div class="flex min-w-0 flex-1 items-center gap-2 rounded-lg border border-line px-2.5 py-1 text-muted focus-within:border-accent-2">
              <Icon name="filter" size={14} />
              <input class="min-w-0 flex-1 border-0! bg-transparent! p-0! text-[0.85rem] text-fg shadow-none! outline-none!" placeholder="Filter headers" aria-label="Filter headers" bind:value={headerFilter} />
            </div>
            <button class="px-2.5 py-1 text-[0.85rem]" onclick={() => copy(view!.headers.map(([k, v]) => `${k}: ${v}`).join('\n'), 'Headers copied')}><Icon name="copy" size={14} /> Copy all</button>
          </div>
          <div class="overflow-hidden rounded-lg border border-line">
            <table class="w-full text-[0.82rem]">
              <tbody>{#each shownHeaders as h (h.i)}<tr class="border-b border-line align-top last:border-b-0 {h.key >= 0 ? '' : 'text-muted'}" {@attach contextMenu(() => [
                { label: 'Copy value', icon: 'copy', run: () => copy(h.v, 'Header copied') },
                { label: 'Copy header line', icon: 'copy', run: () => copy(`${h.k}: ${h.v}`, 'Header copied') },
              ])}><td class="mono w-40 bg-sunken px-3 py-1.5 whitespace-nowrap {h.key >= 0 ? 'font-medium text-fg' : ''}">{h.k}</td><td class="untrusted mono px-3 py-1.5 break-all">{h.v}</td></tr>{/each}</tbody>
            </table>
            {#if !shownHeaders.length}<p class="m-0 px-3 py-2 text-[0.85rem] text-muted">No header matches “{headerFilter}”.</p>{/if}
          </div>
        {:else}
          <div class="mb-2 flex items-center gap-2">
            <span class="flex-1 text-[0.85rem] text-muted">Exactly as backed up{source ? ` · ${bytes(new TextEncoder().encode(source).length)}` : ''}</span>
            <button class="px-2.5 py-1 text-[0.85rem]" disabled={!source} onclick={() => copy(source, 'Source copied')}><Icon name="copy" size={14} /> Copy</button>
            <button class="px-2.5 py-1 text-[0.85rem]" onclick={saveRaw}><Icon name="download" size={14} /> Save .eml…</button>
          </div>
          <pre class="m-0 max-h-[70vh] overflow-auto rounded-lg border border-line bg-sunken px-3 py-2.5 font-mono text-[0.78rem] leading-relaxed whitespace-pre-wrap break-all">{source || 'Loading…'}</pre>
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

  {#if composer}<div class="pr-4 pb-5 pl-4 md:pr-6 md:pl-[4.75rem]">{@render composer()}</div>{/if}
</section>
