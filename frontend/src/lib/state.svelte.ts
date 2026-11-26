// Session, scan list, theme and the toast (design §3).
import { api, setCsrf } from './api';

export const session = $state({ loaded: false, username: '', version: '', csrf: '' });
export const scans = $state({ loaded: false, error: '', items: [] as any[] });
export const toast = $state({ text: '', action: '', href: '', id: 0 });

export async function loadSession(): Promise<boolean> {
  try {
    const s = await api('/session', { noRedirect: true });
    session.username = s.username;
    session.version = s.version;
    session.csrf = s.csrf_token;
    setCsrf(s.csrf_token);
    session.loaded = true;
    return true;
  } catch {
    session.loaded = true;
    session.username = '';
    return false;
  }
}

export async function loadScans(): Promise<void> {
  try {
    const r = await api('/scans?page_size=1000');
    scans.items = r.items;
    scans.error = '';
  } catch (e: any) {
    scans.error = e.message;
  } finally {
    scans.loaded = true;
  }
}

export function latestCompleted(): any | null {
  return scans.items.find((s) => s.status === 'completed') ?? null;
}
/** The scan last opened under /s/{id}: the top bar keeps showing it on /scans and /diff (design §3). */
export const lastScan = $state({ id: null as number | null });
/** Diff A/B: the query, else the two newest completed scans (design §4.12). Used by Diff and the shell's banner. */
export function diffPair(query: URLSearchParams): [number, number] {
  const completed = scans.items.filter((s) => s.status === 'completed');
  const defA = completed[1]?.id ?? completed[0]?.id ?? 0;
  const defB = completed[0]?.id ?? 0;
  return [+(query.get('a') ?? defA), +(query.get('b') ?? defB)];
}
export function runningScan(): any | null {
  return scans.items.find((s) => s.running) ?? null;
}
export function scanById(id: number): any | null {
  return scans.items.find((s) => s.id === id) ?? null;
}

let toastTimer: number | undefined;
export function showToast(text: string, action = '', href = '') {
  toast.text = text;
  toast.action = action;
  toast.href = href;
  toast.id++;
  clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => (toast.text = ''), 6000);
}

// ---- theme: System / Light / Dark in localStorage 'sshbite.theme', never on the server
export type ThemePref = 'system' | 'light' | 'dark';
export const theme = $state({ pref: 'system' as ThemePref, resolved: 'light' as 'light' | 'dark' });
const mq = window.matchMedia('(prefers-color-scheme: dark)');
function applyTheme() {
  theme.resolved = theme.pref === 'system' ? (mq.matches ? 'dark' : 'light') : theme.pref;
  document.documentElement.dataset.theme = theme.resolved;
}
export function initTheme() {
  let p: string | null = null;
  try { p = localStorage.getItem('sshbite.theme'); } catch { /* storage blocked */ }
  theme.pref = p === 'light' || p === 'dark' ? p : 'system';
  applyTheme();
  mq.addEventListener('change', applyTheme);
}
export function setTheme(p: ThemePref) {
  theme.pref = p;
  try {
    if (p === 'system') localStorage.removeItem('sshbite.theme');
    else localStorage.setItem('sshbite.theme', p);
  } catch { /* ignore */ }
  applyTheme();
}

/** A loadable value with loading/error state; loading shows only after 300 ms (design §3). */
export class Resource<T> {
  data = $state<T | null>(null);
  error = $state<string>('');
  errorCode = $state<string>('');
  loading = $state(false);
  slow = $state(false);
  #seq = 0;
  async load(fn: () => Promise<T>, keep = false): Promise<void> {
    const seq = ++this.#seq;
    this.loading = true;
    this.error = '';
    this.errorCode = '';
    if (!keep) this.data = null;
    const t = window.setTimeout(() => { if (seq === this.#seq) this.slow = true; }, 300);
    try {
      const d = await fn();
      if (seq === this.#seq) this.data = d;
    } catch (e: any) {
      if (seq === this.#seq) { this.error = e.message ?? String(e); this.errorCode = e.code ?? ''; }
    } finally {
      clearTimeout(t);
      if (seq === this.#seq) { this.loading = false; this.slow = false; }
    }
  }
}

// ---- the running scan, polled every 2 s while one exists (design §3, §4.2)
export const live = $state({ scan: null as any, prevRunning: 0 });
let liveTimer: number | undefined;
export function startLivePolling() {
  const tick = async () => {
    const r = runningScan();
    if (r) {
      try { live.scan = await api(`/scans/${r.id}`); } catch { /* keep the last value */ }
      live.prevRunning = r.id;
    } else if (live.prevRunning) {
      const done = scanById(live.prevRunning);
      if (done && done.status === 'completed') showToast(`Scan #${done.id} completed.`, `Show scan #${done.id}`, `/s/${done.id}/`);
      live.prevRunning = 0;
      live.scan = null;
    }
  };
  clearInterval(liveTimer);
  liveTimer = window.setInterval(async () => {
    if (!session.username) return;
    await loadScans();
    await tick();
  }, 2000);
  tick();
}
