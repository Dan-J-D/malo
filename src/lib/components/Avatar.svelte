<script lang="ts">
  // Initial on a tinted disc; the hue is derived from the address so a sender keeps one colour everywhere.
  let { name, seed = name, size = 36 }: { name: string; seed?: string; size?: number } = $props();
  const letter = $derived((name.replace(/^["'\s<]+/, '')[0] ?? '?').toUpperCase());
  const hue = $derived([...seed.toLowerCase()].reduce((h, c) => (h * 31 + c.charCodeAt(0)) % 360, 7));
</script>

<span
  class="grid flex-none place-items-center rounded-full font-semibold bg-[hsl(var(--h)_70%_90%)] text-[hsl(var(--h)_55%_30%)] dark:bg-[hsl(var(--h)_40%_26%)] dark:text-[hsl(var(--h)_80%_86%)]"
  style="--h: {hue}; width: {size}px; height: {size}px; font-size: {Math.round(size * 0.42)}px"
  aria-hidden="true">{letter}</span>
