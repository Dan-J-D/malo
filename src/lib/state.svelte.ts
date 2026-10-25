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
  newlyFound: [] as T.MessageSummary[],
  latestReport: null as T.CheckReport | null,
  notices: [] as { id: number; level: string; message: string }[],
});

/** Account chosen in the sidebar switcher; '' shows mail from every account. */
export const scope = $state({ account: '' });

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
      break;
    case 'job_progress': {
      const j = live.jobs.find((x) => x.id === ev.job_id);
      if (j) j.progress = ev.progress;
      break;
    }
    case 'new_message_discovered':
      if (!live.newlyFound.some((m) => m.id === ev.message.id)) {
        live.newlyFound.unshift(ev.message);
        if (live.newlyFound.length > 1000) live.newlyFound.length = 1000;
      }
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
    case 'accounts_changed':
      void refreshAccounts();
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

export async function enterApp(me: T.Me) {
  session.me = me;
  session.lockedReason = null;
  // Route first, so a page left open by a previous user (e.g. Admin) never mounts for this one.
  route.path = '/dashboard';
  go('/dashboard');
  session.phase = 'app';
  live.newlyFound = [];
  scope.account = '';
  await Promise.all([refreshAccounts(), refreshDestinations(), refreshJobs()]).catch((e) => notify(errorText(e), 'error'));
  live.latestReport = await api.get<T.CheckReport | null>('/checks/latest').catch(() => null);
  await app.subscribe((batch) => batch.events.forEach(handle));
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
