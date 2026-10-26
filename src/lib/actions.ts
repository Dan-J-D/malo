// Actions offered in more than one place (sidebar, pages, context menus, the command palette).
import { api } from './api/client';
import type * as T from './api/types';
import { live, scope, go, attempt, refreshAccounts } from './state.svelte';
import { copy, type Entry } from './menu.svelte';

export function backup(a: T.AccountView) {
  return attempt(() => api.post('/jobs', { kind: { type: 'backup', account_id: a.id } }), 'Backup queued');
}

/** Backs up the account chosen in the switcher, or every account. */
export function backupAll() {
  const list = live.accounts.filter((a) => a.enabled && !a.imported && (!scope.account || a.id === scope.account));
  if (!list.length) return;
  return attempt(
    () => Promise.all(list.map((a) => api.post('/jobs', { kind: { type: 'backup', account_id: a.id } }))),
    list.length === 1 ? 'Backup queued' : `${list.length} backups queued`,
  );
}

export function verifyAll(deep: boolean) {
  return attempt(() => api.post('/jobs', { kind: { type: 'check', scope: { scope: 'all' }, deep } }), 'Check queued');
}

export function verifyAccount(a: T.AccountView, deep: boolean) {
  return attempt(() => api.post('/jobs', { kind: { type: 'check', scope: { scope: 'account', account_id: a.id }, deep } }), 'Check queued');
}

export async function removeAccount(a: T.AccountView) {
  if (!confirm(`Remove "${a.name}"? Backups already written stay on your destinations; only the local index rows are deleted.`)) return;
  await attempt(() => api.del(`/accounts/${a.id}`), 'Account removed');
  if (scope.account === a.id) scope.account = '';
  await refreshAccounts();
}

/** Everything that can be done with one account, as context-menu entries. */
export function accountMenu(a: T.AccountView): Entry[] {
  return [
    { label: 'Show in Mail', icon: 'inbox', run: () => { scope.account = a.id; go('/browse'); } },
    { label: 'Show new mail', icon: 'mail', run: () => go(`/browse?account=${a.id}&new=1`) },
    '-',
    !a.imported && { label: 'Back up now', icon: 'refresh', run: () => backup(a) },
    { label: 'Quick verify', icon: 'shield', run: () => verifyAccount(a, false) },
    { label: 'Deep verify', icon: 'shield', run: () => verifyAccount(a, true) },
    '-',
    { label: a.imported ? 'Set up sign-in…' : 'Edit account…', icon: 'pencil', run: () => go(`/accounts/edit/${a.id}`) },
    !a.imported && { label: 'Purge settings', icon: 'trash', run: () => go(`/purge?account=${a.id}`) },
    { label: 'Copy address', icon: 'copy', run: () => copy(a.username, 'Address copied') },
    '-',
    { label: 'Remove account…', icon: 'x', danger: true, run: () => removeAccount(a) },
  ];
}
