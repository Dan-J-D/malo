<script lang="ts">
  let { values = $bindable() }: { values: Record<string, string> } = $props();
  let k = $state('');
  let v = $state('');
  function add() {
    if (!k.trim()) return;
    values = { ...values, [k.trim()]: v };
    k = v = '';
  }
  function remove(key: string) {
    const { [key]: _, ...rest } = values;
    values = rest;
  }
</script>

<table>
  <tbody>
    {#each Object.entries(values) as [key, val]}
      <tr>
        <td class="mono">{key}</td>
        <td><input value={val} oninput={(e) => (values = { ...values, [key]: (e.target as HTMLInputElement).value })} /></td>
        <td><button onclick={() => remove(key)} aria-label="Remove option">✕</button></td>
      </tr>
    {/each}
    <tr>
      <td><input bind:value={k} placeholder="option" /></td>
      <td><input bind:value={v} placeholder="value" /></td>
      <td><button onclick={add}>Add</button></td>
    </tr>
  </tbody>
</table>
