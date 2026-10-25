export function bytes(n: number | bigint | null | undefined): string {
  const v = Number(n ?? 0);
  if (v < 1024) return `${v} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let x = v / 1024;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
  return `${x.toFixed(x < 10 ? 1 : 0)} ${units[i]}`;
}

export function when(ts: string | null | undefined): string {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleString();
}

/** Compact list date: time today, "Mar 29" this year, "Mar 29, 2024" before. */
export function shortDate(ts: string | null | undefined): string {
  if (!ts) return '';
  const d = new Date(ts);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  return d.toLocaleDateString(undefined, d.getFullYear() === now.getFullYear() ? { month: 'short', day: 'numeric' } : { month: 'short', day: 'numeric', year: 'numeric' });
}

export function ago(ts: string | null | undefined): string {
  if (!ts) return 'never';
  const s = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
  const f = (n: number, u: string) => `${n} ${u}${n === 1 ? '' : 's'}`;
  if (s < -60) return `in ${until(ts)}`;
  if (s < 60) return 'just now';
  if (s < 3600) return `${f(Math.floor(s / 60), 'minute')} ago`;
  if (s < 86400) return `${f(Math.floor(s / 3600), 'hour')} ago`;
  return `${f(Math.floor(s / 86400), 'day')} ago`;
}

export function until(ts: string | null | undefined): string {
  if (!ts) return '—';
  let s = Math.max(0, Math.round((new Date(ts).getTime() - Date.now()) / 1000));
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  return h > 0 ? `${h} h ${m} min` : m > 0 ? `${m} min` : `${s} s`;
}

export function jobLabel(kind: import('./api/types').JobKind, accountName: (id: string) => string, destName: (id: string) => string): string {
  const scope = (s: import('./api/types').CheckScope) =>
    s.scope === 'all' ? 'everything' : s.scope === 'account' ? accountName(s.account_id) : destName(s.destination_id);
  switch (kind.type) {
    case 'backup': return `Backup · ${accountName(kind.account_id)}`;
    case 'check': return `${kind.deep ? 'Deep' : 'Quick'} check · ${scope(kind.scope)}`;
    case 'purge_dry_run': return `Purge dry run · ${accountName(kind.account_id)}`;
    case 'purge': return `Purge · ${accountName(kind.account_id)}`;
    case 'repair': return `Repair · ${scope(kind.scope)}`;
    case 'rebuild_index': return `Rebuild index · ${destName(kind.destination_id)}`;
    case 'rebuild_index_all': return 'Rebuild index · all destinations';
  }
}

// Zero-width, bidi-override and other invisible characters (same set as the server's).
const INVISIBLE =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u2028-\u202F\u205F-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF0-\uFFFB]|\uDB40[\uDC00-\uDFFF]|\uD834[\uDD73-\uDD7A]/g;

/** Untrusted text with hidden characters made visible, e.g. "invoice⟨U+202E⟩fdp.exe". */
export function reveal(s: string | null | undefined): string {
  if (!s) return '';
  return s.replace(INVISIBLE, (c) => `⟨U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}⟩`);
}
