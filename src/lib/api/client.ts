// Typed wrappers around the Tauri commands. The session token lives in the Rust side only.
import { invoke, Channel } from '@tauri-apps/api/core';
import type * as T from './types';

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

function toError(e: unknown): ApiError {
  const s = typeof e === 'string' ? e : e instanceof Error ? e.message : JSON.stringify(e);
  const m = /^(\d{3})\|([^|]*)\|([\s\S]*)$/.exec(s);
  if (m) return new ApiError(Number(m[1]), m[2], m[3] || `Request failed (HTTP ${m[1]})`);
  return new ApiError(0, 'client', s || 'Request failed');
}

async function call<R>(cmd: string, args?: Record<string, unknown>): Promise<R> {
  try {
    return await invoke<R>(cmd, args);
  } catch (e) {
    throw toError(e);
  }
}

export const api = {
  get: <R>(path: string) => call<R>('api', { method: 'GET', path, body: null }),
  post: <R>(path: string, body?: unknown) => call<R>('api', { method: 'POST', path, body: body ?? null }),
  put: <R>(path: string, body?: unknown) => call<R>('api', { method: 'PUT', path, body: body ?? null }),
  del: <R>(path: string) => call<R>('api', { method: 'DELETE', path, body: null }),
};

/** A pinned server whose certificate changed; null stands for a publicly trusted certificate. */
export interface CertChange { url: string; old: string | null; new: string | null }

/** The certificate change behind an error from `connectRemote`, if that's what it is. */
export function certChange(e: unknown): CertChange | null {
  if (!(e instanceof ApiError) || e.code !== 'cert_changed') return null;
  try {
    return JSON.parse(e.message) as CertChange;
  } catch {
    return null;
  }
}

export interface Probe { url: string; fingerprint: string | null; publicly_trusted: boolean; status: T.ServerStatus }
export interface LocalInfo { url: string; fingerprint: string | null; status: T.ServerStatus; setup_token: string | null }
/** `url` and `fingerprint`: the server older versions remembered, until a profile holds it. */
export interface Prefs { tray_mode: boolean; recent_profiles: string[]; remember_recent: boolean; url: string | null; fingerprint: string | null }
/** An encrypted connection profile file. The pinned certificate and any password stay in Rust. */
export interface ProfileInfo { path: string; name: string; local: boolean; url: string | null; username: string | null; has_password: boolean }
export interface RecentProfile { path: string; name: string; exists: boolean }
export interface Profiles { recent: RecentProfile[]; remember_recent: boolean; open: ProfileInfo | null }
export interface Unlocked {
  profile: ProfileInfo; url: string; local: boolean; status: T.ServerStatus; setup_token: string | null;
  /** Logged in with the password kept in the profile. */
  me: T.Me | null;
  /** Why logging in with the kept password failed. */
  login_error: string | null;
}
export interface LocalDataInfo { path: string; exists: boolean; bytes: number; files: number; users: number; running: boolean }
export interface OAuthRequest {
  provider: T.OAuthProvider; auth_url: string; token_url: string; client_id: string;
  client_secret: string | null; scopes: string[]; login_hint: string | null;
}

export const app = {
  probe: (url: string) => call<Probe>('probe_server', { url }),
  connectRemote: (url: string, fingerprint: string | null, replacePin = false) =>
    call<T.ServerStatus>('connect_remote', { url, fingerprint, replacePin }),
  startLocal: () => call<LocalInfo>('start_local'),
  prefs: () => call<Prefs>('get_prefs'),
  setTrayMode: (enabled: boolean) => call<void>('set_tray_mode', { enabled }),
  disconnect: () => call<void>('disconnect'),
  profiles: () => call<Profiles>('profiles'),
  pickProfile: () => call<string | null>('pick_profile'),
  unlockProfile: (path: string, password: string) => call<Unlocked>('unlock_profile', { path, password }),
  closeProfile: () => call<void>('close_profile'),
  forgetProfile: (path: string) => call<void>('forget_profile', { path }),
  setRememberRecent: (enabled: boolean) => call<void>('set_remember_recent', { enabled }),
  /** Saves the current connection as a profile file the user picks; null when cancelled. */
  saveProfile: (password: string, loginPassword: string | null) =>
    call<ProfileInfo | null>('save_profile', { password, loginPassword }),
  setProfileLogin: (password: string | null) => call<ProfileInfo>('set_profile_login', { password }),
  changeProfilePassword: (password: string) => call<void>('change_profile_password', { password }),
  login: (username: string, password: string) => call<T.Me>('login', { username, password }),
  logout: (lock: boolean) => call<void>('logout', { lock }),
  subscribe(onBatch: (b: T.EventBatch) => void) {
    const ch = new Channel<T.EventBatch>();
    ch.onmessage = onBatch;
    return call<void>('subscribe_events', { onEvent: ch });
  },
  saveAttachment: (messageId: number, index: number, filename: string) =>
    call<string | null>('save_attachment', { messageId, index, filename }),
  saveRaw: (messageId: number) => call<string | null>('save_raw', { messageId }),
  /** Saves messages as .eml files into a folder the user picks: [folder, count saved]. */
  saveRawMany: (messageIds: number[]) => call<[string, number] | null>('save_raw_many', { messageIds }),
  rawSource: (messageId: number) => call<string>('raw_source', { messageId }),
  saveRecoveryKit: (username: string, password: string, passphrase: string) =>
    call<string | null>('save_recovery_kit', { username, password, passphrase }),
  pickRecoveryKit: () => call<T.RecoveryKitFile | null>('pick_recovery_kit'),
  openExternal: (url: string) => call<void>('open_external', { url }),
  localDataInfo: () => call<LocalDataInfo>('local_data_info'),
  revealLocalData: () => call<void>('reveal_local_data'),
  resetLocalData: (confirm: string, resetPreferences: boolean) =>
    call<void>('reset_local_data', { confirm, resetPreferences }),
  oauthAuthorize: (req: OAuthRequest) => call<{ refresh_token: string }>('oauth_authorize', { req }),
};

export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const parts = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '' && v !== false)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  return parts.length ? `?${parts.join('&')}` : '';
}
