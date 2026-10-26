// One context menu for the whole app. Elements opt in with `{@attach contextMenu(() => [...])}`;
// right-clicking anything else falls back to the app menu, and fields keep the native one.
import type { Attachment } from 'svelte/attachments';
import { notify, errorText } from './state.svelte';

export type MenuItem = {
  label: string;
  icon?: string;
  /** Shortcut shown beside the item (same spec as a command's keys). */
  keys?: string;
  run: () => unknown;
  disabled?: boolean;
  danger?: boolean;
};
/** '-' is a separator; falsy entries are skipped, so items can be written as `cond && {...}`. */
export type Entry = MenuItem | '-' | false | null | undefined | '' | 0;

/** `keyboard`: opened from the keyboard, so the first item takes focus (from the mouse, none does). */
export const menu = $state({ open: false, keyboard: false, x: 0, y: 0, items: [] as (MenuItem | '-')[] });

let returnFocus: HTMLElement | null = null;

function tidy(entries: Entry[]): (MenuItem | '-')[] {
  const out: (MenuItem | '-')[] = [];
  for (const e of entries) {
    if (!e) continue;
    if (e === '-' && (out.length === 0 || out[out.length - 1] === '-')) continue;
    out.push(e);
  }
  if (out[out.length - 1] === '-') out.pop();
  return out;
}

export function openMenu(x: number, y: number, entries: Entry[], keyboard = false) {
  const items = tidy(entries);
  if (!items.length) return;
  returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  Object.assign(menu, { open: true, keyboard, x, y, items });
}

export function closeMenu(restore = false) {
  menu.open = false;
  if (restore) returnFocus?.focus();
  returnFocus = null;
}

/** Opens the menu for a contextmenu event. Selected text inside `within` adds a Copy item on top. */
export function showMenu(e: MouseEvent, entries: Entry[], within?: Element) {
  e.preventDefault();
  const text = getSelection()?.toString() ?? '';
  const sel = getSelection();
  const inside = !within || (sel?.anchorNode && within.contains(sel.anchorNode));
  const head: Entry[] = text.trim() && inside ? [{ label: 'Copy', icon: 'copy', keys: 'mod+c', run: () => copy(text) }, '-'] : [];
  // A menu opened from the keyboard has no pointer position; it opens under the element instead.
  const keyboard = e.button !== 2;
  if (keyboard && e.currentTarget instanceof Element && e.clientX === 0 && e.clientY === 0) {
    const r = e.currentTarget.getBoundingClientRect();
    openMenu(r.left + 8, r.bottom, [...head, ...entries], true);
  } else {
    openMenu(e.clientX, e.clientY, [...head, ...entries], keyboard);
  }
}

/** Opens the menu under an element, for a shortcut that shows an item's actions. */
export function menuUnder(el: Element | null | undefined, entries: Entry[]) {
  if (!el) return;
  const r = el.getBoundingClientRect();
  openMenu(r.left + 12, Math.min(r.bottom, innerHeight - 8), entries, true);
}

/** Gives an element its own context menu. Right-clicks inside a field still get the native menu. */
export function contextMenu(get: () => Entry[]): Attachment<HTMLElement> {
  return (node) => {
    const on = (e: MouseEvent) => {
      if (e.defaultPrevented) return;
      if ((e.target as HTMLElement).closest('input, textarea, select, [contenteditable]')) return;
      showMenu(e, get(), node);
    };
    node.addEventListener('contextmenu', on);
    return () => node.removeEventListener('contextmenu', on);
  };
}

export async function copy(text: string, what = 'Copied to the clipboard') {
  try {
    await navigator.clipboard.writeText(text);
    notify(what, 'success');
  } catch (e) {
    notify(`Couldn't copy: ${errorText(e)}`, 'error');
  }
}
