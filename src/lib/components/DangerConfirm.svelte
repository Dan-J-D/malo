<script lang="ts">
  import type { Snippet } from 'svelte';
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';
  import { errorText } from '../state.svelte';

  // Two-step confirmation for irreversible actions:
  // step 1 explains the consequences and needs an explicit "I understand";
  // step 2 needs the exact phrase typed (and optionally the password).
  let {
    title,
    phrase,
    action,
    needsPassword = false,
    onconfirm,
    onclose,
    children,
  }: {
    title: string;
    phrase: string;
    action: string;
    needsPassword?: boolean;
    onconfirm: (password: string) => Promise<void>;
    onclose: () => void;
    children: Snippet;
  } = $props();

  let step = $state(1);
  let understood = $state(false);
  let typed = $state('');
  let password = $state('');
  let busy = $state(false);
  let error = $state('');

  async function confirm(e: SubmitEvent) {
    e.preventDefault();
    if (typed !== phrase) return;
    busy = true;
    error = '';
    try {
      await onconfirm(password);
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
      password = '';
    }
  }

  const solidDanger = 'bg-bad! text-white! hover:bg-bad/85!';
</script>

<Modal {title} {onclose}>
  <div class="-mt-1 mb-4 flex items-center gap-3">
    <span class="grid size-9 flex-none place-items-center rounded-full bg-bad/15 text-bad"><Icon name="alert" size={17} /></span>
    <div class="flex flex-1 items-center gap-2 text-[0.85rem] text-muted">
      <span>Step {step} of 2</span>
      <span class="flex gap-1" aria-hidden="true">
        <span class="h-1 w-6 rounded-full bg-bad"></span>
        <span class="h-1 w-6 rounded-full transition-colors duration-300 {step === 2 ? 'bg-bad' : 'bg-line'}"></span>
      </span>
    </div>
  </div>

  {#if step === 1}
    <!-- The caller's explanation: paragraphs, a list, and optional extra options as inline labels. -->
    <div class="flex flex-col gap-3 text-[0.92rem] leading-relaxed [&_.mono]:block [&_.mono]:rounded-lg [&_.mono]:bg-raised [&_.mono]:px-3 [&_.mono]:py-2 [&>label.check]:mt-1 [&>p]:m-0 [&>ul]:m-0">
      {@render children()}
    </div>
    <label class="check mt-5 rounded-lg border border-bad/35 bg-bad/8 px-3 py-2.5">
      <input type="checkbox" bind:checked={understood} /> I understand this cannot be undone
    </label>
    <div class="mt-6 flex justify-end gap-2 border-t border-line pt-4">
      <button class="bg-transparent" onclick={onclose}>Cancel</button>
      <button class={solidDanger} disabled={!understood} onclick={() => (step = 2)}>Continue</button>
    </div>
  {:else}
    <form onsubmit={confirm}>
      <label>
        <span>Type <code class="rounded-md bg-raised px-1.5 py-0.5 text-bad">{phrase}</code> to confirm</span>
        <input bind:value={typed} autocomplete="off" spellcheck="false" />
      </label>
      {#if needsPassword}
        <label>Your password <input type="password" bind:value={password} required autocomplete="current-password" /></label>
      {/if}
      {#if error}<p class="callout bad">{error}</p>{/if}
      <div class="mt-6 flex justify-end gap-2 border-t border-line pt-4">
        <button type="button" class="mr-auto bg-transparent" onclick={() => (step = 1)}>Back</button>
        <button type="button" class="bg-transparent" onclick={onclose}>Cancel</button>
        <button class={solidDanger} type="submit" disabled={busy || typed !== phrase || (needsPassword && !password)}>{busy ? 'Working…' : action}</button>
      </div>
    </form>
  {/if}
</Modal>
