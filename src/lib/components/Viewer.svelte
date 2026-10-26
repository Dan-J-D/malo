<script lang="ts">
  import { api, app, qs } from '../api/client';
  import type * as T from '../api/types';
  import { attempt, errorText, notify, live } from '../state.svelte';
  import type { Snippet } from 'svelte';
  import { untrack } from 'svelte';
  import { bytes, when, reveal, dateRange, fileKind, personName, addressOf, CATEGORIES, isGmail, type Category } from '../format';
  import { fly } from 'svelte/transition';
  import { ms, ease } from '../motion';
  import { commands } from '../commands.svelte';
  import { contextMenu, copy, menuUnder, type Entry } from '../menu.svelte';
  import Avatar from './Avatar.svelte';
  import Icon from './Icon.svelte';
  import ThreadMessage from './ThreadMessage.svelte';
  import Composer, { type ComposeInit } from './Composer.svelte';

  // A message with the rest of its conversation, oldest first. The opened message and the newest
  // one start expanded. Replies and forwards are written inline, under the message they answer.
  // `toolbar` holds the caller's navigation controls (close, previous, next).
  let {
    id,
    toolbar,
    ondelete,
  }: { id: number; toolbar?: Snippet; ondelete?: (m: T.MessageSummary, scope: T.DeleteScope) => void } = $props();

  let thread: T.MessageSummary[] = $state([]);
  let expanded: number[] = $state([]);
  let views: Record<number, T.MessageView> = $state({});
  let composing: { at: number; init: ComposeInit } | null = $state(null);
  let error = $state('');
  let scroller: HTMLElement | undefined = $state();

  async function load(mid: number) {
    error = '';
    try {
      const t = await api.get<T.MessageSummary[]>(`/messages/${mid}/thread`);
      if (mid !== id) return;
      thread = t;
      const last = t[t.length - 1]?.id;
      expanded = [...new Set([mid, last].filter((x): x is number => x !== undefined))];
    } catch (e) {
      error = errorText(e);
    }
  }

  $effect(() => {
    const mid = id;
    untrack(() => {
      thread = [];
      views = {};
      composing = null;
      scroller?.scrollTo({ top: 0, behavior: 'instant' });
    });
    load(mid);
  });

  // Opening a message marks it read (tracked by Malo, never via the mail server's \Seen flag).
  $effect(() => {
    const mid = id;
    api.post('/messages/reviewed', { ids: [mid], all: false, account_id: null, reviewed: true }).catch(() => undefined);
    const nf = live.newlyFound.find((m) => m.id === mid);
    if (nf) nf.reviewed = true;
  });

  const opened = $derived(thread.find((m) => m.id === id));
  const account = $derived(live.accounts.find((a) => a.id === opened?.account_id));
  const category = $derived.by((): Category | null => {
    if (!opened || !isGmail(account)) return null;
    const c = (opened.category ?? 'primary') as Category;
    return c in CATEGORIES ? c : null;
  });
  const span = $derived.by(() => {
    const dates = thread.map((m) => m.envelope.date ?? m.internal_date).filter((d): d is string => !!d).sort();
    return dateRange(dates[0], dates[dates.length - 1]);
  });
  const people = $derived.by(() => {
    const seen = new Map<string, { name: string; address: string }>();
    for (const m of thread) {
      const add = (name: string | null | undefined, address: string) => {
        const k = address.toLowerCase();
        if (k && !seen.has(k)) seen.set(k, { name: reveal(name || personName(address)), address });
      };
      add(m.envelope.from_name, m.envelope.from);
      m.envelope.to.forEach((t) => add(null, addressOf(t)));
    }
    return [...seen.values()];
  });
  const attachments = $derived(
    thread.flatMap((m) => (views[m.id]?.attachments ?? []).map((a) => ({ m, a }))),
  );

  function toggle(mid: number) {
    expanded = expanded.includes(mid) ? expanded.filter((x) => x !== mid) : [...expanded, mid];
  }

  async function save(mid: number, a: T.AttachmentInfo) {
    if (a.warnings.length && !confirm(`Warning:\n- ${a.warnings.join('\n- ')}\n\nSave "${a.filename}" anyway? Malo never opens attachments.`)) return;
    const p = await attempt(() => app.saveAttachment(mid, a.index, a.filename));
    if (p) notify(`Saved to ${p}`, 'success');
  }

  const prefixed = (p: string, s: string) => (new RegExp(`^${p}:`, 'i').test(s.trim()) ? s.trim() : `${p}: ${s.trim()}`);

  /** Opens the composer under message `mid`, filled in for a reply, reply-all or forward. */
  async function reply(mid: number, mode: 'reply' | 'reply-all' | 'forward') {
    const m = thread.find((x) => x.id === mid);
    if (!m) return;
    let v = views[mid];
    if (!v) {
      const got = await attempt(() => api.get<T.MessageView>(`/messages/${mid}/view${qs({ html: false, remote: false })}`));
      if (!got) return;
      v = views[mid] = got;
    }
    if (!expanded.includes(mid)) expanded = [...expanded, mid];
    const acc = live.accounts.find((a) => a.id === m.account_id);
    const me = (acc?.username ?? '').toLowerCase();
    const sender = v.from_name ? `${v.from_name} <${v.from}>` : v.from;
    const mine = v.from.toLowerCase() === me;
    const quoted = v.text.replace(/\r\n/g, '\n').replace(/\n+$/, '').split('\n').map((l) => (l.startsWith('>') ? `>${l}` : `> ${l}`)).join('\n');
    const date = when(v.date);
    let to: string[] = [];
    let cc: string[] = [];
    let subject: string;
    let body: string;
    if (mode === 'forward') {
      subject = prefixed('Fwd', v.subject);
      const head = [`From: ${sender}`, `Date: ${date}`, `Subject: ${v.subject}`, `To: ${v.to.join(', ')}`, ...(v.cc.length ? [`Cc: ${v.cc.join(', ')}`] : [])];
      body = `\n\n---------- Forwarded message ----------\n${head.join('\n')}\n\n${v.text}`;
    } else {
      subject = prefixed('Re', v.subject);
      // A reply to your own message goes to the people you wrote to.
      to = mine ? [...v.to] : v.reply_to.length ? [...v.reply_to] : [sender];
      if (mode === 'reply-all') {
        const taken = new Set([me, ...to.map(addressOf)]);
        cc = [...(mine ? [] : v.to), ...v.cc].filter((r) => {
          const a = addressOf(r);
          if (taken.has(a)) return false;
          taken.add(a);
          return true;
        });
      }
      body = `\n\nOn ${date}, ${sender} wrote:\n${quoted}\n`;
    }
    composing = {
      at: mid,
      init: {
        account_id: m.account_id,
        title: mode === 'forward' ? 'Forward' : mode === 'reply-all' ? 'Reply all' : `Reply to ${reveal(v.from_name || v.from)}`,
        message: {
          to,
          cc,
          bcc: [],
          subject,
          body,
          in_reply_to: mode === 'forward' ? undefined : mid,
          attachments_of: mode === 'forward' && v.attachments.length ? mid : undefined,
        },
        forwarded: mode === 'forward' ? v.attachments.map((a) => ({ filename: a.filename, size: Number(a.size) })) : undefined,
      },
    };
  }

  const many = $derived(!!opened && opened.envelope.to.length > 1);

  function moreMenu(): Entry[] {
    if (!opened) return [];
    const subject = reveal(opened.envelope.subject);
    return [
      { label: 'Reply', icon: 'reply', keys: 'r', run: () => reply(id, 'reply') },
      { label: 'Reply all', icon: 'reply-all', keys: 'a', run: () => reply(id, 'reply-all') },
      { label: 'Forward', icon: 'forward', keys: 'f', run: () => reply(id, 'forward') },
      '-',
      thread.length > 1 && { label: expanded.length === thread.length ? 'Collapse all' : 'Expand all', icon: 'layers', run: () => (expanded = expanded.length === thread.length ? [id] : thread.map((m) => m.id)) },
      subject && { label: 'Copy subject', icon: 'copy', run: () => copy(subject, 'Subject copied') },
      { label: 'Save .eml…', icon: 'download', keys: 'mod+s', run: () => attempt(() => app.saveRaw(id)) },
    ];
  }

  function deleteMenu(): Entry[] {
    if (!opened || !ondelete) return [];
    return [
      { label: 'Delete from mail server…', icon: 'trash', keys: 'delete', danger: true, run: () => ondelete(opened!, 'server') },
      { label: 'Delete from backup…', icon: 'trash', keys: 'shift+delete', danger: true, run: () => ondelete(opened!, 'everywhere') },
    ];
  }

  commands(() => {
    if (!opened) return [];
    return [
      { id: 'reply', group: 'Message', label: 'Reply', keys: 'r', run: () => reply(id, 'reply') },
      { id: 'reply-all', group: 'Message', label: 'Reply all', keys: 'a', run: () => reply(id, 'reply-all') },
      { id: 'forward', group: 'Message', label: 'Forward', keys: 'f', run: () => reply(id, 'forward') },
    ];
  });
</script>

<div class="flex h-12 flex-none items-center gap-1 border-b border-line px-3">
  {@render toolbar?.()}
  <span class="flex-1"></span>
  {#if opened}
    <button class="px-2.5 py-1 text-[0.85rem]" onclick={() => reply(id, many ? 'reply-all' : 'reply')} title={many ? 'Reply all (a)' : 'Reply (r)'}>
      <Icon name={many ? 'reply-all' : 'reply'} size={14} /> {many ? 'Reply all' : 'Reply'}
    </button>
    {#if many}<button class="p-1.5" onclick={() => reply(id, 'reply')} aria-label="Reply" title="Reply (r)"><Icon name="reply" size={15} /></button>{/if}
    <button class="p-1.5" onclick={() => reply(id, 'forward')} aria-label="Forward" title="Forward (f)"><Icon name="forward" size={15} /></button>
    <button class="p-1.5" onclick={(e) => menuUnder(e.currentTarget, moreMenu())} aria-label="More actions" title="More"><Icon name="more" size={15} /></button>
    {#if ondelete}
      <button class="bg-bad/15 p-1.5 text-bad hover:bg-bad! hover:text-white" onclick={(e) => menuUnder(e.currentTarget, deleteMenu())} aria-label="Delete" title="Delete"><Icon name="trash" size={15} /></button>
    {/if}
  {/if}
</div>

<div bind:this={scroller} class="min-h-0 flex-1 overflow-y-auto">
  {#if error}
    <p class="callout bad m-6">{error}</p>
  {:else if !opened}
    <p class="m-6 text-muted">Loading…</p>
  {:else}
    {#key id}
    <article class="flex flex-col" in:fly={{ y: 8, duration: ms(240), easing: ease }} {@attach contextMenu(moreMenu)}>
      <header class="flex flex-col gap-3 px-6 pt-5 pb-4">
        <div>
          <h2 class="subject m-0 text-[1.15rem] leading-snug font-medium">{reveal(opened.envelope.subject) || '(no subject)'}{#if thread.length > 1}<span class="ml-1.5 font-normal text-faint tabular-nums">[{thread.length}]</span>{/if}</h2>
          {#if span}<div class="mt-1.5 flex items-center gap-1.5 text-[0.85rem] text-muted"><Icon name="calendar" size={14} /> {span}</div>{/if}
        </div>
        <div class="flex flex-wrap items-center gap-x-1 gap-y-1.5">
          {#if category}
            {@const c = CATEGORIES[category]}
            <span class="mr-2 flex items-center gap-1.5 rounded-md px-2 py-1 text-[0.8rem] {c.bg} {c.tone}" title="Gmail category"><Icon name={c.icon} size={13} /> {c.label}</span>
          {/if}
          {#each people.slice(0, 6) as p (p.address)}
            <span class="flex items-center gap-1.5 rounded-full py-0.5 pr-2 pl-0.5 text-[0.85rem]" title={p.address}
              {@attach contextMenu(() => [{ label: 'Copy address', icon: 'copy', run: () => copy(p.address, 'Address copied') }])}>
              <Avatar name={p.name} seed={p.address} size={20} /><span class="untrusted max-w-[12rem] truncate">{p.name}</span>
            </span>
          {/each}
          {#if people.length > 6}<span class="text-[0.85rem] text-faint" title={people.slice(6).map((p) => p.address).join(', ')}>+{people.length - 6}</span>{/if}
        </div>
      </header>

      {#if attachments.length}
        <section class="px-6 pb-4">
          <div class="mb-2 text-[0.9rem] text-muted">Attachments <span class="text-faint">[{attachments.length}]</span></div>
          <div class="flex flex-wrap gap-2">
            {#each attachments as { m, a } (`${m.id}-${a.index}`)}
              {@const k = fileKind(a.filename, a.sniffed_type ?? a.declared_type)}
              <button class="max-w-full gap-2 border px-2.5 py-1.5 text-[0.9rem] {a.warnings.length ? 'border-bad/40 bg-bad/8' : 'border-transparent'}"
                onclick={() => save(m.id, a)} title="Save as…">
                <span class={a.warnings.length ? 'text-bad' : k.tone}><Icon name={a.warnings.length ? 'alert' : k.icon} size={15} /></span>
                <span class="untrusted truncate">{reveal(a.filename)}</span>
                <span class="flex-none text-muted">{bytes(a.size)}</span>
              </button>
            {/each}
          </div>
        </section>
      {/if}

      <div class="border-t border-line">
        {#each thread as m (m.id)}
          <ThreadMessage {m} expanded={expanded.includes(m.id)} focus={m.id === id}
            ontoggle={() => toggle(m.id)} onreply={(mode) => reply(m.id, mode)} onview={(v) => (views[m.id] = v)}
            composer={composing?.at === m.id ? inlineComposer : undefined} />
        {/each}
      </div>
    </article>
    {/key}
  {/if}
</div>

{#snippet inlineComposer()}
  {#if composing}
    {#key composing.init}
      <Composer inline init={composing.init} onclose={() => (composing = null)} />
    {/key}
  {/if}
{/snippet}
