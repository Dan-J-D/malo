<script lang="ts" module>
  /** What the composer starts with. */
  export interface ComposeInit {
    account_id: string;
    message: import('../api/types').SendRequest;
    /** The draft it continues. */
    draft_id?: number;
    /** Attachments that go along with a forward. */
    forwarded?: { filename: string; size: number }[];
    title: string;
  }
</script>

<script lang="ts">
  import { untrack } from 'svelte';
  import { api } from '../api/client';
  import type * as T from '../api/types';
  import { live, notify, errorText, go } from '../state.svelte';
  import { bytes, reveal, fileKind } from '../format';
  import Icon from './Icon.svelte';
  import Select from './Select.svelte';
  import Recipients from './Recipients.svelte';

  // Writes a message (new, reply or forward) and sends it through the account's SMTP server.
  // It is saved as a draft (encrypted, in Malo only) a moment after each change.
  let {
    init,
    onclose,
    onsent,
    inline = false,
  }: { init: ComposeInit; onclose: () => void; onsent?: () => void; inline?: boolean } = $props();

  const start = untrack(() => init);
  let accountId = $state(start.account_id);
  let to = $state(start.message.to);
  let cc = $state(start.message.cc ?? []);
  let bcc = $state(start.message.bcc ?? []);
  let showCc = $state((start.message.cc ?? []).length + (start.message.bcc ?? []).length > 0);
  let subject = $state(start.message.subject);
  let body = $state(start.message.body);
  let keepAttachments = $state(start.message.attachments_of !== undefined && start.message.attachments_of !== null);
  let draftId = $state<number | undefined>(start.draft_id);
  let saved = $state<'idle' | 'saving' | 'saved' | 'failed'>(start.draft_id ? 'saved' : 'idle');
  let sending = $state(false);
  let error = $state('');
  let dirty = false;
  let textarea: HTMLTextAreaElement | undefined = $state();

  const senders = $derived(live.accounts.filter((a) => !a.imported));
  const account = $derived(live.accounts.find((a) => a.id === accountId));
  const canSend = $derived(!!account?.smtp && to.length + cc.length + bcc.length > 0 && !sending);

  function message(): T.SendRequest {
    return {
      from: start.message.from,
      to,
      cc,
      bcc,
      subject,
      body,
      in_reply_to: start.message.in_reply_to,
      attachments_of: keepAttachments ? start.message.attachments_of : undefined,
      draft_id: draftId,
    };
  }

  // Replies start in the text, above the quote.
  $effect(() => {
    if (!textarea || start.message.to.length === 0) return;
    textarea.focus();
    textarea.setSelectionRange(0, 0);
  });

  let saveTimer: ReturnType<typeof setTimeout>;
  let saving: Promise<void> | null = null;
  $effect(() => {
    void [accountId, to, cc, bcc, subject, body, keepAttachments];
    if (!untrack(() => dirty)) {
      dirty = true;
      return;
    }
    untrack(() => {
      clearTimeout(saveTimer);
      saveTimer = setTimeout(save, 1200);
    });
  });
  $effect(() => () => clearTimeout(saveTimer));

  async function save() {
    clearTimeout(saveTimer);
    if (sending) return;
    await saving;
    saved = 'saving';
    saving = (async () => {
      try {
        const d = await api.put<T.DraftView>('/drafts', { id: draftId, account_id: accountId, message: { ...message(), draft_id: undefined } } satisfies T.DraftInput);
        draftId = d.id;
        saved = 'saved';
      } catch {
        saved = 'failed';
      }
    })();
    await saving;
    saving = null;
  }

  async function send() {
    if (!canSend) return;
    clearTimeout(saveTimer);
    await saving;
    sending = true;
    error = '';
    try {
      const r = await api.post<T.SendResult>(`/accounts/${accountId}/send`, message());
      notify(r.saved_to ? `Sent · copy saved in ${r.saved_to}` : 'Sent', 'success');
      onsent?.();
      onclose();
    } catch (e) {
      error = errorText(e);
    } finally {
      sending = false;
    }
  }

  async function discard() {
    clearTimeout(saveTimer);
    await saving;
    if (draftId !== undefined) await api.del(`/drafts/${draftId}`).catch(() => undefined);
    onclose();
  }

  /** Closing keeps what was written as a draft. */
  async function close() {
    if (dirty && saved !== 'saved') await save();
    if (draftId !== undefined && (to.length || subject || body.trim())) notify('Saved as a draft', 'info');
    onclose();
  }

  function onkeydown(e: KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      e.stopPropagation();
      void send();
    } else if (e.key === 'Escape' && !e.defaultPrevented) {
      e.preventDefault();
      e.stopPropagation();
      void close();
    }
  }
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<section class="flex flex-col {inline ? 'pop-down rounded-xl border border-line bg-sunken' : 'h-full'}" aria-label={init.title} {onkeydown}>
  <header class="flex items-center gap-2 border-b border-line px-4 py-2">
    <Icon name={init.title.startsWith('Forward') ? 'forward' : init.title.startsWith('Reply') ? 'reply' : 'draft'} size={15} />
    <span class="font-medium">{init.title}</span>
    <span class="flex-1"></span>
    <span class="text-[0.8rem] text-faint" aria-live="polite">
      {saved === 'saving' ? 'Saving…' : saved === 'saved' ? 'Draft saved' : saved === 'failed' ? 'Not saved' : ''}
    </span>
    <button type="button" class="bg-transparent p-1 text-muted hover:text-fg" onclick={close} aria-label="Close and keep the draft" title="Close and keep the draft (Esc)"><Icon name="x" size={15} /></button>
  </header>

  <div class="flex flex-col divide-y divide-line px-4">
    {#if !start.message.in_reply_to && senders.length > 1}
      <div class="flex items-center gap-2 py-1.5">
        <span class="w-10 flex-none text-[0.85rem] text-muted">From</span>
        <Select variant="ghost" class="text-[0.9rem]" label="Send from" bind:value={accountId}
          options={senders.map((a) => ({ value: a.id, label: `${a.name} · ${a.username}`, disabled: !a.smtp }))} />
      </div>
    {/if}
    <div class="flex items-start gap-2 py-1.5">
      <Recipients label="To" bind:value={to} account={accountId} autofocus={start.message.to.length === 0} />
      {#if !showCc}<button type="button" class="mt-0.5 bg-transparent px-1.5 py-0.5 text-[0.85rem] text-muted hover:text-fg" onclick={() => (showCc = true)}>Cc Bcc</button>{/if}
    </div>
    {#if showCc}
      <div class="py-1.5"><Recipients label="Cc" bind:value={cc} account={accountId} /></div>
      <div class="py-1.5"><Recipients label="Bcc" bind:value={bcc} account={accountId} /></div>
    {/if}
    <div class="flex items-center gap-2 py-1.5">
      <span class="w-10 flex-none text-[0.85rem] text-muted">Subject</span>
      <input bind:value={subject} aria-label="Subject" class="min-w-0 flex-1 border-0 bg-transparent px-0 py-1 font-medium shadow-none outline-none focus-visible:outline-none" />
    </div>
  </div>

  <textarea bind:this={textarea} bind:value={body} aria-label="Message"
    class="mx-4 my-3 min-h-[12rem] resize-y border-0 bg-transparent p-0 leading-relaxed shadow-none outline-none focus-visible:outline-none {inline ? '' : 'flex-1'}"
    placeholder="Write your message"></textarea>

  {#if init.forwarded?.length}
    <div class="mx-4 mb-3 flex flex-wrap items-center gap-2 text-[0.85rem]">
      <label class="check"><input type="checkbox" bind:checked={keepAttachments} /> Include {init.forwarded.length === 1 ? 'the attachment' : `the ${init.forwarded.length} attachments`}</label>
      {#if keepAttachments}
        {#each init.forwarded as f}
          {@const k = fileKind(f.filename, '')}
          <span class="flex items-center gap-1.5 rounded-lg bg-raised px-2 py-1"><span class={k.tone}><Icon name={k.icon} size={13} /></span><span class="untrusted">{reveal(f.filename)}</span><span class="text-faint">{bytes(f.size)}</span></span>
        {/each}
      {/if}
    </div>
  {/if}

  {#if error}<p class="callout bad mx-4 my-0 mb-3 text-[0.9rem]">{error}</p>{/if}
  {#if account && !account.smtp}
    <p class="callout mx-4 my-0 mb-3 text-[0.9rem]">Sending isn't set up for {account.name}. <button type="button" class="link" onclick={() => go('/accounts')}>Add its outgoing server</button> under Accounts.</p>
  {/if}

  <footer class="flex items-center gap-2 border-t border-line px-4 py-2.5">
    <button type="button" class="primary" disabled={!canSend} onclick={send} title="Send (Ctrl+Enter)">
      <Icon name="send" size={14} /> {sending ? 'Sending…' : 'Send'}
    </button>
    <span class="text-[0.8rem] text-faint">Ctrl+Enter</span>
    <span class="flex-1"></span>
    <button type="button" class="bg-transparent text-muted hover:text-bad" onclick={discard} title="Delete this draft"><Icon name="trash" size={14} /> Discard</button>
  </footer>
</section>
