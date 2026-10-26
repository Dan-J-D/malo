<script lang="ts">
  import { onDestroy, tick } from 'svelte';
  import { fly, slide } from 'svelte/transition';
  import { ms, ease } from '../motion';
  import { session, route, live, scope, go, logout } from '../state.svelte';
  import { until } from '../format';
  import Icon from './Icon.svelte';
  import Avatar from './Avatar.svelte';
  import { navRail } from '../layout.svelte';
  import { contextMenu } from '../menu.svelte';
  import { accountMenu, backupAll, verifyAll } from '../actions';

  // Icon rail: the sidebar dragged narrow. Labels move into tooltips, counts become dots.
  const rail = $derived(navRail());

  const core = [
    ['/browse', 'Mail', 'inbox'],
    ['/dashboard', 'Overview', 'gauge'],
    ['/activity', 'Activity', 'activity'],
  ];
  const manage = [
    ['/accounts', 'Accounts', 'at'],
    ['/destinations', 'Destinations', 'database'],
    ['/integrity', 'Integrity', 'shield'],
    ['/purge', 'Purge', 'trash'],
  ];
  let manageOpen = $state(true);
  let now = $state(Date.now());
  const timer = setInterval(() => (now = Date.now()), 30_000);
  onDestroy(() => clearInterval(timer));
  const running = $derived(live.jobs.filter((j) => j.state === 'running' || j.state === 'queued').length);
  const unseen = $derived(live.newlyFound.filter((m) => !m.reviewed).length);
  // The live feed keeps only the newest messages; past that the count is a lower bound.
  const unseenText = $derived(live.foundCount > live.newlyFound.length && unseen === live.newlyFound.length ? `${unseen}+` : String(unseen));
  const total = $derived(live.accounts.reduce((n, a) => n + Number(a.message_count), 0));
  const lockIn = $derived.by(() => {
    void now;
    return until(session.me?.expires_at);
  });
  // "Back up now" follows the switcher: the chosen account, or every account.
  const backupable = $derived(live.accounts.filter((a) => a.enabled && !a.imported && (!scope.account || a.id === scope.account)));

  // Account switcher: up to four avatars inline; the menu always lists every account.
  const inline = 4;
  let menuOpen = $state(false);
  let switcher: HTMLElement | undefined = $state();
  // On the rail the menu opens beside the sidebar (the sidebar scrolls, so it would be clipped).
  let menuAt = $state({ left: 0, top: 0 });
  function toggleMenu() {
    if (!menuOpen && rail && switcher) {
      const r = switcher.getBoundingClientRect();
      menuAt = { left: r.right + 6, top: r.top };
    }
    menuOpen = !menuOpen;
  }
  const current = $derived(live.accounts.find((a) => a.id === scope.account) ?? null);
  const hidden = $derived(Math.max(0, live.accounts.length - inline));

  function pick(id: string) {
    scope.account = id;
    menuOpen = false;
    if (!route.path.startsWith('/browse') || /^\/browse\/\d/.test(route.path)) go('/browse');
  }

  // One highlight slides between links instead of each link lighting up on its own.
  let navEl: HTMLElement | undefined = $state();
  let mark = $state({ top: 0, height: 0, shown: false, animate: false });
  async function place() {
    await tick();
    const a = navEl?.querySelector<HTMLElement>('a[aria-current="page"]');
    if (!navEl || !a) { mark.shown = false; return; }
    mark = { top: a.offsetTop, height: a.offsetHeight, shown: true, animate: mark.shown };
  }
  $effect(() => {
    void route.path; void manageOpen; void live.accounts.length; void scope.account; void session.me?.role; void rail;
    place();
  });

  const allMenu = () => [
    { label: 'Show all mail', icon: 'inbox', run: () => pick('') },
    { label: 'Back up all accounts now', icon: 'refresh', run: () => { scope.account = ''; backupAll(); } },
    { label: 'Quick verify everything', icon: 'shield', run: () => verifyAll(false) },
    '-' as const,
    { label: 'Add account…', icon: 'plus', run: () => go('/accounts/new') },
    { label: 'Manage accounts', icon: 'settings', run: () => go('/accounts') },
  ];
</script>

<nav bind:this={navEl} class="relative flex h-screen flex-col gap-4 overflow-x-hidden overflow-y-auto pt-3.5 pb-2.5 {rail ? 'px-2' : 'pr-2.5 pl-3'}">
  <span aria-hidden="true"
    class="pointer-events-none absolute top-0 rounded-lg {rail ? 'right-2 left-2' : 'right-2.5 left-3'} bg-panel shadow-sm dark:bg-raised dark:shadow-none {mark.animate ? 'transition-[transform,height] duration-300 ease-[cubic-bezier(0.22,1,0.36,1)]' : ''} {mark.shown ? '' : 'opacity-0'}"
    style="transform: translateY({mark.top}px); height: {mark.height}px"></span>
  <div class="relative flex flex-col gap-3" bind:this={switcher}>
    <div class="flex items-center gap-1.5 {rail ? 'flex-col' : 'px-1'}">
      <button class="grid size-8 place-items-center rounded-lg p-0 {scope.account === '' ? 'bg-panel text-fg ring-2 ring-accent-2 dark:bg-raised' : 'bg-transparent text-muted hover:text-fg'}"
        onclick={() => pick('')} title="All accounts" aria-label="All accounts" aria-pressed={scope.account === ''} {@attach contextMenu(allMenu)}><Icon name="layers" /></button>
      {#each live.accounts.slice(0, inline) as a (a.id)}
        <button class="relative rounded-full bg-transparent! p-0 hover:scale-110 {scope.account === a.id ? 'ring-2 ring-accent-2 ring-offset-2 ring-offset-frame' : 'opacity-75 hover:opacity-100'}"
          onclick={() => pick(a.id)} title="{a.name} · {a.username}" aria-label="Show {a.name}" aria-pressed={scope.account === a.id} {@attach contextMenu(() => accountMenu(a))}>
          <Avatar name={a.name} seed={a.username} size={28} />
          {#if a.last_backup_ok === false}<span class="absolute -right-0.5 -bottom-0.5 size-2.5 rounded-full bg-warn ring-2 ring-frame" title="Last backup had errors"></span>{/if}
        </button>
      {/each}
      {#if hidden > 0}
        <button class="h-7 rounded-full px-2 text-xs text-muted" onclick={toggleMenu} title="{hidden} more accounts">+{hidden}</button>
      {/if}
      {#if !rail}
      <a href="#/accounts/new" class="grid size-7 place-items-center rounded-full border border-dashed border-line text-muted no-underline! hover:border-muted hover:text-fg" title="Add an email account" aria-label="Add an email account"><Icon name="plus" size={14} /></a>
      <span class="flex-1"></span>
      {/if}
      <button class="bg-transparent p-1.5 text-muted hover:text-fg" onclick={toggleMenu} aria-haspopup="menu" aria-expanded={menuOpen} aria-label="All accounts" title="All accounts"><Icon name="more" /></button>
    </div>

    {#if !rail}
    <div class="min-w-0 px-1.5">
      <div class="truncate font-semibold">{current ? current.name : 'All accounts'}</div>
      <div class="truncate text-[0.85rem] text-muted">
        {current ? current.username : `${live.accounts.length} ${live.accounts.length === 1 ? 'account' : 'accounts'} · ${total.toLocaleString()} messages`}
      </div>
    </div>
    {/if}

    {#if menuOpen}
      <div transition:fly={{ y: -6, duration: ms(160), easing: ease }}
        style={rail ? `position: fixed; left: ${menuAt.left}px; top: ${menuAt.top}px; width: 17rem` : undefined}
        class="absolute top-10 right-0 left-0 z-40 origin-top flex max-h-[70vh] flex-col overflow-y-auto rounded-xl border border-line bg-panel p-1.5 shadow-2xl shadow-black/30" role="menu" aria-label="Accounts">
        {@render accountItem('', 'All accounts', `${total.toLocaleString()} messages in ${live.accounts.length} accounts`)}
        {#each live.accounts as a (a.id)}
          <div class="contents" {@attach contextMenu(() => accountMenu(a))}>{@render accountItem(a.id, a.name, `${a.username} · ${Number(a.message_count).toLocaleString()}`)}</div>
        {/each}
        <div class="my-1 h-px bg-line"></div>
        <a href="#/accounts" class="flex items-center gap-2.5 rounded-lg px-2 py-1.5 text-muted no-underline! hover:bg-hover hover:text-fg" role="menuitem" onclick={() => (menuOpen = false)}><Icon name="settings" size={15} /> Manage accounts</a>
        <a href="#/accounts/new" class="flex items-center gap-2.5 rounded-lg px-2 py-1.5 text-muted no-underline! hover:bg-hover hover:text-fg" role="menuitem" onclick={() => (menuOpen = false)}><Icon name="plus" size={15} /> Add account</a>
      </div>
    {/if}
  </div>

  <button class="w-full justify-center border border-line bg-panel py-2 dark:bg-raised {rail ? 'px-0' : ''}" disabled={backupable.length === 0} onclick={backupAll}
    title={rail ? 'Back up now (Shift+B)' : 'Shift+B'} aria-label={rail ? 'Back up now' : undefined}>
    <Icon name="refresh" />{#if !rail} Back up now{/if}
  </button>

  <div class="flex flex-col gap-px">
    {#each core as [href, label, icon]}
      {@render link(href, label, icon)}
    {/each}
  </div>

  <div class="flex flex-col gap-px">
    {#if rail}
      <div class="mx-auto mb-1.5 h-px w-6 bg-line" role="presentation"></div>
    {:else}
    <button class="justify-start gap-1 bg-transparent px-2.5 py-1 text-[0.85rem] text-muted hover:bg-transparent! hover:text-fg"
      aria-expanded={manageOpen} onclick={() => (manageOpen = !manageOpen)}>
      Management <span class="inline-flex transition-transform {manageOpen ? '' : '-rotate-90'}"><Icon name="chevron" size={14} /></span>
    </button>
    {/if}
    {#if manageOpen || rail}
      <div class="flex flex-col gap-px" transition:slide={{ duration: ms(200), easing: ease }} onintroend={place} onoutroend={place}>
        {#each manage as [href, label, icon]}
          {@render link(href, label, icon)}
        {/each}
      </div>
    {/if}
  </div>

  <div class="flex-1"></div>

  <div class="flex flex-col gap-px">
    {@render link('/settings', 'Settings', 'settings')}
    {#if session.me?.role === 'admin'}{@render link('/admin', 'Admin', 'key')}{/if}
  </div>

  {#if rail}
  <div class="flex flex-col items-center gap-1 border-t border-line pt-3">
    <span title="{session.me?.username} · {session.local ? 'Local server' : session.url} · keys unlocked for {lockIn}"><Avatar name={session.me?.username ?? '?'} size={26} /></span>
    <button class="bg-transparent p-2 text-muted hover:text-fg" onclick={() => logout(true)} title="Lock now: wipe keys from the server; backups pause until you log in (Ctrl+Shift+L)" aria-label="Lock now"><Icon name="lock" size={15} /></button>
    <button class="bg-transparent p-2 text-muted hover:text-fg" onclick={() => logout(false)} title="Log out" aria-label="Log out"><Icon name="logout" size={15} /></button>
  </div>
  {:else}
  <div class="flex flex-col gap-1.5 border-t border-line px-1.5 pt-3">
    <div class="flex min-w-0 items-center gap-2.5">
      <Avatar name={session.me?.username ?? '?'} size={26} />
      <div class="min-w-0 text-[0.85rem] leading-tight">
        <div class="truncate font-medium">{session.me?.username}</div>
        <div class="truncate text-muted">{session.local ? 'Local server' : session.url}</div>
      </div>
    </div>
    <div class="text-[0.85rem] text-muted" title="Keys are wiped from server memory when this runs out">Keys unlocked for {lockIn}</div>
    <div class="flex gap-1">
      <button class="bg-transparent px-2 py-1 text-[0.85rem] text-muted hover:text-fg" onclick={() => logout(true)}
        title="Wipe keys from the server now; backups pause until you log in (Ctrl+Shift+L)"><Icon name="lock" size={14} /> Lock now</button>
      <button class="bg-transparent px-2 py-1 text-[0.85rem] text-muted hover:text-fg" onclick={() => logout(false)}><Icon name="logout" size={14} /> Log out</button>
    </div>
  </div>
  {/if}
</nav>

<svelte:window
  onresize={place}
  onclick={(e) => menuOpen && !switcher?.contains(e.target as Node) && (menuOpen = false)}
  onkeydown={(e) => e.key === 'Escape' && (menuOpen = false)} />

{#snippet accountItem(id: string, name: string, detail: string)}
  <button class="flex w-full items-center gap-2.5 rounded-lg bg-transparent px-2 py-1.5 text-left hover:bg-hover!" role="menuitemradio" aria-checked={scope.account === id} onclick={() => pick(id)}>
    {#if id}<Avatar name={name} seed={detail.split(" ")[0]} size={26} />{:else}<span class="grid size-[26px] place-items-center rounded-full bg-raised text-muted"><Icon name="layers" size={14} /></span>{/if}
    <span class="min-w-0 flex-1 leading-tight"><span class="block truncate">{name}</span><span class="block truncate text-[0.8rem] text-muted">{detail}</span></span>
    {#if scope.account === id}<span class="text-accent-2"><Icon name="check" size={15} /></span>{/if}
  </button>
{/snippet}

{#snippet link(href: string, label: string, icon: string)}
  {@const active = route.path.startsWith(href)}
  <a href={'#' + href} aria-current={active ? 'page' : undefined} title={rail ? label : undefined}
    class="group relative flex items-center gap-2.5 rounded-lg py-[0.45rem] no-underline! {rail ? 'justify-center px-0' : 'px-2.5'} {active ? 'font-medium text-fg' : 'text-muted hover:bg-hover/60 hover:text-fg'}">
    <span class={active ? 'text-fg' : 'text-faint group-hover:text-muted'}><Icon name={icon} /></span>
    <span class={rail ? 'sr-only' : 'flex-1'}>{label}</span>
    {#if rail}
      {#if href === '/browse' && unseen > 0}<span class="absolute top-1 right-2 size-2 rounded-full bg-accent-2" title="{unseenText} new since last visit"></span>
      {:else if href === '/activity' && running > 0}<span class="absolute top-1 right-2 size-2 animate-pulse rounded-full bg-accent-2" title="{running} job(s) running or queued"></span>
      {:else if href === '/purge' && live.accounts.some((a) => a.policy.armed)}<span class="absolute top-1 right-2 size-2 rounded-full bg-warn" title="Purge is armed on at least one account"></span>
      {/if}
    {:else if href === '/browse'}
      {#if unseen > 0}<span class="rounded-md bg-accent px-1.5 text-xs font-semibold text-white tabular-nums" title="New since last visit">{unseenText}</span>
      {:else if total > 0}<span class="text-faint tabular-nums">{total.toLocaleString()}</span>{/if}
    {:else if href === '/activity' && running > 0}
      <span class="size-2.5 animate-spin rounded-full border-2 border-accent-2 border-r-transparent" title="{running} job(s) running or queued"></span>
      <span class="text-faint tabular-nums">{running}</span>
    {:else if href === '/accounts' && live.accounts.length}<span class="text-faint tabular-nums">{live.accounts.length}</span>
    {:else if href === '/destinations' && live.destinations.length}<span class="text-faint tabular-nums">{live.destinations.length}</span>
    {:else if href === '/purge' && live.accounts.some((a) => a.policy.armed)}<span class="size-[7px] rounded-full bg-warn" title="Purge is armed on at least one account"></span>
    {/if}
  </a>
{/snippet}
