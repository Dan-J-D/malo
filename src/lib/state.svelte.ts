// Global UI state (Svelte 5 runes) fed by REST calls and the live event stream.
import { api, app, ApiError } from './api/client';
import type * as T from './api/types';

export type Phase = 'boot' | 'connect' | 'login' | 'app';

export const session = $state({
  phase: 'boot' as Phase,
  status: null as T.ServerStatus | null,
  me: null as T.Me | null,
  local: false,
  url: '' as string,
  setupToken: null as string | null,
  lockedReason: null as string | null,
});

export const live = $state({
  accounts: [] as T.AccountView[],
  destinations: [] as T.DestinationView[],
  jobs: [] as T.JobInfo[],
  /** Newest discovered messages, at most FOUND_KEEP; the full list is Mail's "New" view. */
  newlyFound: [] as T.MessageSummary[],
  /** Messages discovered since login, including those dropped from `newlyFound`. */
  foundCount: 0,
  latestReport: null as T.CheckReport | null,
  /** The messages last deleted from the backup (a new array each time), so open lists reload. */
  deleted: [] as number[],
  notices: [] as { id: number; level: string; message: string }[],
});

/** Account chosen in the sidebar switcher; '' shows mail from every account. */
export const scope = $state({ account: '' });

// A first backup discovers every message in the mailbox; the live feed only needs the newest.
export const FOUND_KEEP = 200;
const foundIds = new Set<number>();

export const route = $state({ path: location.hash.slice(1) || '/dashboard' });

window.addEventListener('hashchange', () => {
  route.path = location.hash.slice(1) || '/dashboard';
});

export function go(path: string) {
  location.hash = path;
}

let noticeId = 0;
export function notify(message: string, level: 'info' | 'warning' | 'error' | 'success' = 'info') {
  const id = ++noticeId;
  live.notices.push({ id, level, message });
  setTimeout(() => {
    const i = live.notices.findIndex((n) => n.id === id);
    if (i >= 0) live.notices.splice(i, 1);
  }, level === 'error' ? 10000 : 5000);
}

export function errorText(e: unknown): string {
  return e instanceof ApiError || e instanceof Error ? e.message : String(e);
}

/** Runs an action, showing errors as notices; locks the UI on 401/423. */
export async function attempt<R>(fn: () => Promise<R>, success?: string): Promise<R | undefined> {
  try {
    const r = await fn();
    if (success) notify(success, 'success');
    return r;
  } catch (e) {
    if (e instanceof ApiError && (e.status === 401 || e.status === 423)) {
      toLogin(e.message);
    } else {
      notify(errorText(e), 'error');
    }
    return undefined;
  }
}

/** Marks messages reviewed, or new again. Returns false when the request failed (the error is shown). */
export async function setReviewed(ids: number[], reviewed: boolean): Promise<boolean> {
  const r = await attempt(() => api.post<number>('/messages/reviewed', { ids, all: false, account_id: null, reviewed }));
  if (r === undefined) return false;
  live.newlyFound.forEach((m) => { if (ids.includes(m.id)) m.reviewed = reviewed; });
  return true;
}

export function deleteText(r: T.DeleteSummary): string {
  const parts = [];
  if (r.deleted_from_backup) parts.push(`${r.deleted_from_backup} deleted from the backup`);
  if (r.deleted_from_server) parts.push(`${r.deleted_from_server} deleted from the mail server`);
  if (r.skipped) parts.push(`${r.skipped} kept`);
  return parts.join(' · ') || 'nothing to delete';
}

export function accountName(id: string): string {
  return live.accounts.find((a) => a.id === id)?.name ?? id.slice(0, 8);
}

export function destName(id: string): string {
  return live.destinations.find((d) => d.id === id)?.name ?? id.slice(0, 8);
}

export async function refreshAccounts() {
  live.accounts = await api.get<T.AccountView[]>('/accounts');
}

export async function refreshDestinations() {
  live.destinations = await api.get<T.DestinationView[]>('/destinations');
}

export async function refreshJobs() {
  live.jobs = await api.get<T.JobInfo[]>('/jobs?limit=200');
}

export async function refreshMe() {
  session.me = await api.get<T.Me>('/me');
}

function upsertJob(job: T.JobInfo) {
  const i = live.jobs.findIndex((j) => j.id === job.id);
  if (i >= 0) live.jobs[i] = job;
  else live.jobs.unshift(job);
}

function handle(ev: T.SyncEvent) {
  switch (ev.type) {
    case 'job_queued':
    case 'job_started':
      upsertJob(ev.job);
      break;
    case 'job_finished':
      upsertJob(ev.job);
      if (ev.job.state === 'failed') notify(`Job failed: ${ev.job.error ?? 'unknown error'}`, 'error');
      if (ev.job.kind.type === 'backup') void refreshAccounts();
      if (ev.job.kind.type === 'delete_messages' && ev.job.state === 'done' && ev.job.result) {
        const r = ev.job.result as T.DeleteSummary;
        notify(`${accountName(r.account_id)}: ${deleteText(r)}${r.errors.length ? ` — ${r.errors[0]}` : ''}`, r.errors.length ? 'warning' : 'success');
        void refreshAccounts();
      }
      break;
    case 'job_progress': {
      const j = live.jobs.find((x) => x.id === ev.job_id);
      if (j) j.progress = ev.progress;
      break;
    }
    case 'new_message_discovered':
      addFound([ev.message]);
      break;
    case 'message_state_changed': {
      const m = live.newlyFound.find((x) => x.id === ev.id);
      if (m) {
        m.state = ev.state;
        m.stored = ev.stored;
        m.destinations = ev.destinations;
        m.error = ev.error;
      }
      break;
    }
    case 'check_finished':
      live.latestReport = ev.report;
      void refreshDestinations();
      void refreshAccounts();
      break;
    case 'purge_summary':
      notify(
        `Purge of ${accountName(ev.summary.account_id)}: ${ev.summary.deleted} deleted, ${ev.summary.skipped} skipped`,
        ev.summary.errors.length ? 'warning' : 'success',
      );
      break;
    case 'messages_deleted': {
      const gone = new Set(ev.ids);
      live.newlyFound = live.newlyFound.filter((m) => !gone.has(m.id));
      live.deleted = ev.ids;
      break;
    }
    case 'accounts_changed':
      // Also sent when a rebuild restores destinations from a settings copy.
      void refreshAccounts();
      void refreshDestinations();
      break;
    case 'locked':
      toLogin(ev.reason);
      break;
    case 'notice':
      notify(ev.message, ev.level === 'warning' ? 'warning' : 'info');
      break;
    case 'check_progress':
      break;
  }
}

/** Adds discovered messages to the live feed in one update, newest first. */
function addFound(found: T.MessageSummary[]) {
  const fresh = found.filter((m) => !foundIds.has(m.id) && foundIds.add(m.id));
  if (!fresh.length) return;
  live.foundCount += fresh.length;
  live.newlyFound = [...fresh.slice(-FOUND_KEEP).reverse(), ...live.newlyFound].slice(0, FOUND_KEEP);
}

/** A first backup sends discoveries by the hundred; they go into the feed together. Other
 *  events still apply in order, after the discoveries before them. */
function handleBatch(events: T.SyncEvent[]) {
  let found: T.MessageSummary[] = [];
  for (const ev of events) {
    if (ev.type === 'new_message_discovered') {
      found.push(ev.message);
      continue;
    }
    if (found.length) {
      addFound(found);
      found = [];
    }
    handle(ev);
  }
  if (found.length) addFound(found);
}

export function clearFound() {
  live.newlyFound = [];
  live.foundCount = 0;
  foundIds.clear();
}

export async function enterApp(me: T.Me) {
  session.me = me;
  session.lockedReason = null;
  // Route first, so a page left open by a previous user (e.g. Admin) never mounts for this one.
  route.path = '/dashboard';
  go('/dashboard');
  session.phase = 'app';
  clearFound();
  scope.account = '';
  await Promise.all([refreshAccounts(), refreshDestinations(), refreshJobs()]).catch((e) => notify(errorText(e), 'error'));
  live.latestReport = await api.get<T.CheckReport | null>('/checks/latest').catch(() => null);
  await app.subscribe((batch) => handleBatch(batch.events));
  if (me.skipped_while_locked > 0) {
    notify(`${me.skipped_while_locked} scheduled job(s) were skipped while you were locked.`, 'warning');
  }
}

export function toLogin(reason: string | null) {
  session.lockedReason = reason;
  session.me = null;
  session.phase = 'login';
}

export async function logout(lock: boolean) {
  await app.logout(lock).catch(() => undefined);
  toLogin(lock ? 'Locked — keys were wiped from the server.' : null);
}
