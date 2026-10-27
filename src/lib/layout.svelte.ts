// Pane widths (sidebar, message list), remembered on this device. The sidebar collapses to an
// icon rail when dragged narrow; dragging it back out restores the full sidebar.

export const NAV_RAIL = 60;
export const NAV_MIN = 200;
export const NAV_MAX = 360;
export const NAV_DEFAULT = 248;
export const LIST_MIN = 280;
export const LIST_MAX = 720;
export const LIST_DEFAULT = 380;

const KEY = 'malo.panes';

function saved(): { nav?: number; list?: number } {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? '{}');
  } catch {
    return {};
  }
}

const s = saved();
export const panes = $state({
  nav: typeof s.nav === 'number' ? s.nav : NAV_DEFAULT,
  list: typeof s.list === 'number' ? s.list : LIST_DEFAULT,
});

export function savePanes() {
  try {
    localStorage.setItem(KEY, JSON.stringify(panes));
  } catch {
    // private window or blocked storage: widths just don't persist
  }
}

/** Sidebar width for a dragged width: below the midpoint between rail and minimum it snaps to the rail. */
export function navWidth(w: number): number {
  if (w < (NAV_RAIL + NAV_MIN) / 2) return NAV_RAIL;
  return Math.min(NAV_MAX, Math.max(NAV_MIN, w));
}

export const navRail = () => panes.nav <= NAV_RAIL;

/** Phone-sized window: one pane at a time, and a tab bar (with the sidebar as a drawer) instead
 *  of the sidebar. */
export const screen = $state({
  phone: false,
  drawer: false,
  /** Writing a message: the tab bar steps aside, as it does while reading one. */
  writing: false,
});
if (typeof window !== 'undefined') {
  const mq = window.matchMedia('(max-width: 767px)');
  screen.phone = mq.matches;
  mq.addEventListener('change', (e) => {
    screen.phone = e.matches;
    if (!e.matches) screen.drawer = false;
  });
}
