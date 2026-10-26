<script lang="ts">
  // The app's global commands, the command palette (Ctrl+K) and the shortcut sheet (?), plus the
  // fallback context menu for anything that has no menu of its own.
  import { tick } from 'svelte';
  import { fade, scale } from 'svelte/transition';
  import { ms, ease } from '../motion';
  import { commands, all, caps, type Command } from '../commands.svelte';
  import { showMenu, type Entry } from '../menu.svelte';
  import { session, live, scope, route, go, logout } from '../state.svelte';
  import { backupAll, verifyAll, backup } from '../actions';
  import { panes, savePanes, navRail, NAV_DEFAULT, NAV_RAIL } from '../layout.svelte';
  import Icon from './Icon.svelte';
  import Modal from './Modal.svelte';

  let palette = $state(false);
  let sheet = $state(false);
  let q = $state('');
  let active = $state(0);
  let input: HTMLInputElement | undefined = $state();
  let list: HTMLElement | undefined = $state();

  function cycleAccount(d: number) {
    const ids = ['', ...live.accounts.map((a) => a.id)];
    const i = ids.indexOf(scope.account);
    scope.account = ids[(i + d + ids.length) % ids.length];
  }

  const pages: [string, string, string][] = [
    ['m', '/browse', 'Mail'], ['o', '/dashboard', 'Overview'], ['a', '/activity', 'Activity'],
    ['c', '/accounts', 'Accounts'], ['d', '/destinations', 'Destinations'], ['i', '/integrity', 'Integrity'],
    ['p', '/purge', 'Purge'], ['s', '/settings', 'Settings'],
  ];

  commands(() => [
    { id: 'palette', group: 'General', label: 'Command palette', keys: 'mod+k, mod+shift+p', anywhere: true, run: () => (palette ? close() : openPalette()) },
    { id: 'shortcuts', group: 'General', label: 'Keyboard shortcuts', keys: '?', run: () => (sheet = true) },
    { id: 'sidebar', group: 'General', label: navRail() ? 'Expand sidebar' : 'Collapse sidebar', keys: 'mod+b', run: toggleRail },
    { id: 'back', group: 'General', label: 'Go back', keys: 'alt+arrowleft', run: () => history.back() },
    { id: 'forward', group: 'General', label: 'Go forward', keys: 'alt+arrowright', run: () => history.forward() },
    { id: 'backup-all', group: 'Backups', label: scope.account ? 'Back up this account now' : 'Back up all accounts now', keys: 'shift+b', run: backupAll },
    { id: 'verify', group: 'Backups', label: 'Quick verify everything', run: () => verifyAll(false) },
    { id: 'verify-deep', group: 'Backups', label: 'Deep verify everything', run: () => verifyAll(true) },
    ...pages.map(([k, href, label]): Command => ({ id: `go-${href}`, group: 'Go to', label, keys: `g ${k}`, run: () => go(href) })),
    { id: 'go-new', group: 'Go to', label: 'New mail', keys: 'g n', run: () => go('/browse?new=1') },
    ...(session.me?.role === 'admin' ? [{ id: 'go-admin', group: 'Go to', label: 'Admin', keys: 'g x', run: () => go('/admin') }] : []),
    { id: 'add-account', group: 'Accounts', label: 'Add an email account', run: () => go('/accounts/new') },
    { id: 'next-account', group: 'Accounts', label: 'Next account', keys: ']', run: () => cycleAccount(1) },
    { id: 'prev-account', group: 'Accounts', label: 'Previous account', keys: '[', run: () => cycleAccount(-1) },
    { id: 'all-accounts', group: 'Accounts', label: 'Show all accounts', keys: 'alt+0', run: () => (scope.account = '') },
    ...live.accounts.flatMap((a, i): Command[] => [
      { id: `show-${a.id}`, group: 'Accounts', label: `Show ${a.name}`, keys: i < 9 ? `alt+${i + 1}` : undefined, run: () => (scope.account = a.id) },
      { id: `backup-${a.id}`, group: 'Accounts', label: `Back up ${a.name} now`, disabled: a.imported, run: () => backup(a) },
    ]),
    { id: 'lock', group: 'Session', label: 'Lock now (wipe keys from the server)', keys: 'mod+shift+l', run: () => logout(true) },
    { id: 'logout', group: 'Session', label: 'Log out', run: () => logout(false) },
  ]);

  function toggleRail() {
    panes.nav = navRail() ? NAV_DEFAULT : NAV_RAIL;
    savePanes();
  }

  // ── Palette ──
  // Matches when every typed word is found in the group and label; earlier matches rank first.
  const shown = $derived.by(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    const cmds = all().filter((c) => !c.hidden && !c.disabled && c.id !== 'palette');
    const seen = new Set<string>();
    const unique = cmds.reverse().filter((c) => !seen.has(c.id) && seen.add(c.id)).reverse();
    if (!words.length) return unique;
    return unique
      .map((c) => {
        const hay = `${c.label} ${c.group}`.toLowerCase();
        const at = words.map((w) => hay.indexOf(w));
        return { c, score: at.some((i) => i < 0) ? -1 : at.reduce((a, b) => a + b, 0) };
      })
      .filter((x) => x.score >= 0)
      .sort((a, b) => a.score - b.score)
      .map((x) => x.c);
  });
  $effect(() => {
    void q;
    active = 0;
  });

  let before: HTMLElement | null = null;
  async function openPalette() {
    before = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    sheet = false;
    q = '';
    palette = true;
    await tick();
    input?.focus();
  }
  function close() {
    palette = false;
    before?.focus();
  }
  function pick(c: Command | undefined) {
    if (!c) return;
    close();
    c.run();
  }
  function paletteKey(e: KeyboardEvent) {
    const n = shown.length;
    if (e.key === 'ArrowDown' || (e.key === 'n' && e.ctrlKey)) active = (active + 1) % Math.max(1, n);
    else if (e.key === 'ArrowUp' || (e.key === 'p' && e.ctrlKey)) active = (active - 1 + n) % Math.max(1, n);
    else if (e.key === 'Enter') pick(shown[active]);
    else if (e.key === 'Escape') close();
    else return;
    e.preventDefault();
    e.stopPropagation();
    tick().then(() => list?.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' }));
  }

  // ── Shortcut sheet ──
  const groups = $derived.by(() => {
    const by = new Map<string, Command[]>();
    const seen = new Set<string>();
    for (const c of [...all()].reverse()) {
      if (!c.keys || c.hidden || seen.has(c.keys)) continue;
      seen.add(c.keys);
      by.set(c.group, [c, ...(by.get(c.group) ?? [])]);
    }
    return [...by].reverse();
  });

  // Right-click on anything without its own menu: selected text can be copied, and the app's
  // basics are a click away. Fields keep the native menu (cut, copy, paste, spelling).
  function fallback(e: MouseEvent) {
    if (e.defaultPrevented || (e.target as HTMLElement).closest('input, textarea, select, [contenteditable]')) return;
    const entries: Entry[] = [
      { label: 'Back', icon: 'arrow-left', keys: 'alt+arrowleft', run: () => history.back() },
      { label: 'Forward', icon: 'arrow-right', keys: 'alt+arrowright', run: () => history.forward() },
      '-',
      route.path.startsWith('/browse') ? null : { label: 'Mail', icon: 'inbox', keys: 'g m', run: () => go('/browse') },
      { label: 'Command palette…', icon: 'command', keys: 'mod+k', run: openPalette },
      { label: 'Keyboard shortcuts', icon: 'keyboard', keys: '?', run: () => (sheet = true) },
    ];
    showMenu(e, entries);
  }
</script>

<svelte:window oncontextmenu={fallback} />

{#if palette}
  <div transition:fade={{ duration: ms(120) }} class="fixed inset-0 z-[150] flex justify-center bg-black/40 pt-[12vh]" role="presentation"
    onclick={(e) => e.target === e.currentTarget && close()}>
    <div transition:scale={{ start: 0.97, duration: ms(160), easing: ease }} role="dialog" aria-modal="true" aria-label="Command palette"
      class="flex h-fit max-h-[70vh] w-[min(600px,94vw)] flex-col overflow-hidden rounded-xl border border-line bg-panel shadow-2xl shadow-black/40">
      <label class="m-0 flex flex-row items-center gap-2.5 border-b border-line px-4 font-normal">
        <span class="text-faint"><Icon name="search" /></span>
        <input bind:this={input} bind:value={q} onkeydown={paletteKey} placeholder="Type a command…" aria-label="Command"
          role="combobox" aria-expanded="true" aria-controls="palette-list" aria-activedescendant={shown[active] ? `cmd-${active}` : undefined}
          class="flex-1 border-0 bg-transparent px-0 py-3.5 text-[0.95rem] focus-visible:outline-none" />
        <kbd class="rounded-md bg-hover px-1.5 font-sans text-xs text-muted">Esc</kbd>
      </label>
      <div bind:this={list} id="palette-list" role="listbox" aria-label="Commands" class="min-h-0 overflow-y-auto p-1.5">
        {#each shown as c, i (c.id)}
          {#if i === 0 || shown[i - 1].group !== c.group}
            <div class="px-2.5 pt-2 pb-1 text-[0.8rem] text-faint">{c.group}</div>
          {/if}
          <button id="cmd-{i}" role="option" aria-selected={i === active} tabindex="-1" onclick={() => pick(c)} onpointermove={() => (active = i)}
            class="flex w-full items-center gap-3 rounded-lg px-2.5 py-1.5 text-left active:scale-100! {i === active ? 'bg-hover!' : 'bg-transparent hover:bg-transparent!'}">
            <span class="min-w-0 flex-1 truncate">{c.label}</span>
            {#each caps(c.keys) as k}<kbd class="rounded-md bg-raised px-1.5 font-sans text-xs text-muted">{k}</kbd>{/each}
          </button>
        {:else}
          <p class="m-0 px-3 py-6 text-center text-muted">No matching commands.</p>
        {/each}
      </div>
    </div>
  </div>
{/if}

{#if sheet}
  <Modal title="Keyboard shortcuts" onclose={() => (sheet = false)} wide>
    <p class="mt-0 text-[0.9rem] text-muted">Shortcuts change with the page you're on. Shift+F10 or the Menu key opens the actions of the focused item, and every command is in the palette ({caps('mod+k')[0]}).</p>
    <div class="columns-1 gap-8 sm:columns-2">
      {#each groups as [group, cmds]}
        <section class="mb-5 break-inside-avoid">
          <h3 class="mt-0 mb-1.5 text-[0.85rem] text-muted">{group}</h3>
          {#each cmds as c}
            <div class="flex items-center gap-3 border-b border-line py-1.5 text-[0.9rem] last:border-b-0">
              <span class="min-w-0 flex-1 truncate">{c.label}</span>
              {#each caps(c.keys) as k, i}{#if i}<span class="text-[0.8rem] text-faint">then</span>{/if}<kbd class="rounded-md bg-raised px-1.5 font-sans text-xs text-muted">{k}</kbd>{/each}
            </div>
          {/each}
        </section>
      {/each}
    </div>
  </Modal>
{/if}
