<script lang="ts">
  // Vertical drag handle. Reports the width the pane would have (start width + pointer travel);
  // the owner clamps or snaps it. Arrow keys nudge, Home/double-click restores the default.
  let {
    width,
    min,
    max,
    label,
    set,
    reset,
    done,
  }: { width: number; min: number; max: number; label: string; set: (w: number) => void; reset: () => void; done: () => void } = $props();

  let dragging = $state(false);
  let startX = 0;
  let startW = 0;

  function down(e: PointerEvent) {
    if (e.button !== 0) return;
    e.preventDefault();
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    dragging = true;
    startX = e.clientX;
    startW = width;
    document.documentElement.classList.add('resizing');
  }
  function move(e: PointerEvent) {
    if (dragging) set(startW + e.clientX - startX);
  }
  function up() {
    if (!dragging) return;
    dragging = false;
    document.documentElement.classList.remove('resizing');
    done();
  }
  function key(e: KeyboardEvent) {
    const step = e.shiftKey ? 64 : 16;
    if (e.key === 'ArrowLeft') set(width - step);
    else if (e.key === 'ArrowRight') set(width + step);
    else if (e.key === 'Home') reset();
    else return;
    e.preventDefault();
    done();
  }
</script>

<!-- A focusable separator is the ARIA window-splitter pattern; Svelte's a11y rules count it as static. -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
<div
  role="separator"
  aria-orientation="vertical"
  aria-label={label}
  aria-valuenow={Math.round(width)}
  aria-valuemin={min}
  aria-valuemax={max}
  tabindex="0"
  title="Drag to resize · double-click to reset"
  class="group absolute top-0 -right-1 bottom-0 z-20 flex w-2 cursor-col-resize touch-none justify-center outline-none"
  onpointerdown={down}
  onpointermove={move}
  onpointerup={up}
  onpointercancel={up}
  ondblclick={() => { reset(); done(); }}
  onkeydown={key}
>
  <span class="my-3 w-0.5 rounded-full transition-colors {dragging ? 'bg-accent-2' : 'bg-transparent group-hover:bg-line group-focus-visible:bg-accent-2'}"></span>
</div>
