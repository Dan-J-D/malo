// Keyboard shortcuts and the command palette share one list of commands. The app shell adds the
// global ones and each page adds its own while it's mounted; a command with `keys` is also a
// shortcut. Later registrations win, so a page can take over a key the shell also uses.
import { untrack } from 'svelte';
import { menu } from './menu.svelte';

export type Command = {
  id: string;
  label: string;
  /** Heading in the palette and the shortcut sheet. */
  group: string;
  /** 'j', 'shift+u', 'mod+k' (Ctrl, or ⌘ on a Mac), 'g m' (one key, then another); alternatives separated by ', '. */
  keys?: string;
  run: () => unknown;
  disabled?: boolean;
  /** Also fires while typing in a field or with a dialog open (for modifier shortcuts). */
  anywhere?: boolean;
  /** Left out of the palette, e.g. one entry per item that would only add noise there. */
  hidden?: boolean;
};

let sets: Command[][] = $state.raw([]);

export const all = () => sets.flat();

/** Registers commands while the calling component is mounted. `get` is re-read when the state it reads changes. */
export function commands(get: () => Command[]) {
  $effect(() => {
    const list = get();
    untrack(() => (sets = [...sets, list]));
    return () => (sets = sets.filter((s) => s !== list));
  });
}

export const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform);

/** The keydown as key specs to try, best first: modifiers in a fixed order, then the key. Shift is
 *  part of symbols like '?'. A key on the digit row also counts as its digit, after the character it
 *  typed: Option+digit types a symbol on a Mac, and some layouts put '?' or the digits themselves
 *  on shifted digit keys, so neither reading alone works everywhere. */
function combos(e: KeyboardEvent): string[] {
  const typed = combo(e, e.key.toLowerCase());
  const digit = /^Digit\d$/.test(e.code) ? combo(e, e.code.slice(5)) : null;
  return digit && digit !== typed ? [typed, digit] : [typed];
}

function combo(e: KeyboardEvent, key: string): string {
  let k = key;
  if (k === ' ') k = 'space';
  const symbol = k.length === 1 && !/[a-z0-9]/.test(k);
  const parts = [];
  if (isMac ? e.metaKey : e.ctrlKey) parts.push('mod');
  if (isMac && e.ctrlKey) parts.push('ctrl');
  if (e.altKey) parts.push('alt');
  if (e.shiftKey && !symbol) parts.push('shift');
  parts.push(k);
  return parts.join('+');
}

const specs = (c: Command) => c.keys?.split(/,\s*/) ?? [];

/** Key caps for display: 'mod+shift+l' → ['Ctrl+Shift+L'], 'g m' → ['G', 'M']. Only the first alternative. */
export function caps(keys: string | undefined): string[] {
  const first = keys?.split(/,\s*/)[0];
  if (!first) return [];
  const names: Record<string, string> = isMac
    ? { mod: '⌘', shift: '⇧', alt: '⌥', ctrl: '⌃' }
    : { mod: 'Ctrl', shift: 'Shift', alt: 'Alt', ctrl: 'Ctrl' };
  const keyNames: Record<string, string> = {
    arrowdown: '↓', arrowup: '↑', arrowleft: '←', arrowright: '→', escape: 'Esc', enter: 'Enter', space: 'Space',
    home: 'Home', end: 'End', f10: 'F10',
  };
  return first.split(' ').map((c) =>
    c.split('+').map((p) => names[p] ?? keyNames[p] ?? p.toUpperCase()).join(isMac ? '' : '+'),
  );
}

function editable(t: EventTarget | null): boolean {
  return t instanceof HTMLElement && !!t.closest('input, textarea, select, [contenteditable=""], [contenteditable="true"], [role="separator"]');
}

let pending: string | null = null;
let pendingTimer: ReturnType<typeof setTimeout>;

function onKey(e: KeyboardEvent) {
  if (e.defaultPrevented || e.isComposing || menu.open || ['Shift', 'Control', 'Alt', 'Meta'].includes(e.key)) return;
  const tries = combos(e);
  const k = tries[0];
  // Shift+F10 and the Menu key open the focused element's context menu (WebKitGTK doesn't always).
  if ((k === 'shift+f10' || k === 'contextmenu') && document.activeElement instanceof HTMLElement && !editable(document.activeElement)) {
    e.preventDefault();
    const r = document.activeElement.getBoundingClientRect();
    document.activeElement.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: r.left, clientY: r.bottom, button: 0 }));
    return;
  }
  const typing = editable(e.target);
  const dialog = !!document.querySelector('[aria-modal="true"]');
  const usable = all().filter((c) => !c.disabled && (c.anywhere || (!typing && !dialog)));
  const before = pending;
  pending = null;
  clearTimeout(pendingTimer);
  const match = (spec: string) => [...usable].reverse().find((c) => specs(c).includes(spec));
  let hit: Command | undefined;
  for (const t of tries) {
    hit = (before ? match(`${before} ${t}`) : undefined) ?? match(t);
    if (hit) break;
  }
  if (hit) {
    e.preventDefault();
    hit.run();
    return;
  }
  if (!before && usable.some((c) => specs(c).some((s) => s.startsWith(k + ' ')))) {
    e.preventDefault();
    pending = k;
    pendingTimer = setTimeout(() => (pending = null), 1500);
    return;
  }
  if (typing && k === 'escape') (e.target as HTMLElement).blur();
}

if (typeof window !== 'undefined') window.addEventListener('keydown', onKey);
