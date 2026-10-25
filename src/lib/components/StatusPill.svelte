<script lang="ts">
  import type { MessageState } from '../api/types';
  let { state, stored = 0, destinations = 0, error = null }: { state: MessageState; stored?: number; destinations?: number; error?: string | null } = $props();
  const cls = $derived(
    state === 'verified' ? 'ok' : state === 'error' ? 'bad' : state === 'stored' ? 'info' : state === 'downloading' ? 'info' : 'muted',
  );
  const text = $derived(
    state === 'stored' ? `stored ${stored}/${destinations}` : state === 'error' ? 'error · retry' : state,
  );
</script>

<span class="pill {cls}" title={error ?? ''}>{text}</span>
