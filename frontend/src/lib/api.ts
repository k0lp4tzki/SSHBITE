// API client: JSON, CSRF header on writes, a 401 sends the user to the login page (design §3).
import { navigate, route } from './router.svelte';

export class ApiError extends Error {
  status: number;
  code: string;
  body: any;
  constructor(status: number, code: string, message: string, body: any = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

let csrf = '';
export function setCsrf(token: string) { csrf = token; }

export function qs(params: Record<string, unknown>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '' || (Array.isArray(v) && v.length === 0)) continue;
    p.set(k, Array.isArray(v) ? v.join(',') : String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown; noRedirect?: boolean } = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf;
  let res: Response;
  try {
    res = await fetch('/api' + path, { method, headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      credentials: 'same-origin' });
  } catch {
    throw new ApiError(0, 'network', "Can't reach the SSHBITE server.");
  }
  if (res.status === 204) return undefined as T;
  let body: any = null;
  try { body = await res.json(); } catch { body = null; }
  if (!res.ok) {
    const err = body?.error ?? {};
    if (res.status === 401 && !opts.noRedirect && err.code === 'unauthenticated') {
      const here = route.path + route.search;
      if (route.path !== '/login') navigate('/login' + qs({ next: here, expired: 1 }), true);
    }
    throw new ApiError(res.status, err.code ?? 'http_error', err.message ?? `HTTP ${res.status}`, err);
  }
  return body as T;
}

export const fpUrl = (fp: string) => fp.replace(/\+/g, '-').replace(/\//g, '_');
export const fpFromUrl = (s: string) => s.replace(/-/g, '+').replace(/_/g, '/');
