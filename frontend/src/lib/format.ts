// Words and numbers (design §6.3, §7).
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n: number) => String(n).padStart(2, '0');

export function parseTime(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const d = new Date(iso);
  return isNaN(d.getTime()) ? null : d;
}
/** Local time, "26 Nov 2026 02:00". */
export function fmtTime(iso: string | null | undefined): string {
  const d = parseTime(iso);
  if (!d) return '–';
  return `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
export function fmtClock(iso: string | null | undefined): string {
  const d = parseTime(iso);
  return d ? `${pad(d.getHours())}:${pad(d.getMinutes())}` : '–';
}
export function utcTitle(iso: string | null | undefined): string {
  const d = parseTime(iso);
  return d ? d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : '';
}
export function fmtDuration(a: string | null | undefined, b: string | null | undefined): string {
  const x = parseTime(a), y = parseTime(b);
  if (!x || !y) return '–';
  const s = Math.max(0, Math.round((y.getTime() - x.getTime()) / 1000));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
}
export const n = (v: number | null | undefined) => (v === null || v === undefined ? '–' : v.toLocaleString('en-US'));
export const plural = (v: number, one: string, many = one + 's') => `${n(v)} ${v === 1 ? one : many}`;

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];
export const SEV_LABEL: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
export const STRENGTHS = ['critical', 'weak', 'ok', 'good', 'unknown'] as const;
export const STRENGTH_LABEL: Record<string, string> = { critical: 'Critical', weak: 'Weak', ok: 'OK', good: 'Good', unknown: 'Unknown' };
/** strength -> colour class and glyph */
export const STRENGTH_SEV: Record<string, string> = { critical: 'critical', weak: 'medium', ok: 'low', good: 'good', unknown: 'info' };
export const STRENGTH_GLYPH: Record<string, string> = { critical: 'critical', weak: 'medium', ok: 'dot', good: 'good', unknown: 'unknown' };

export const RULES: Record<string, string> = {
  key_strength_critical: 'Critical key algorithm ({alg} {bits})',
  key_strength_weak: 'Weak key ({alg} {bits})',
  root_authorized_key: 'Key can log in as root',
  key_on_many_hosts: 'Key authorized on {n} hosts',
  key_unknown_origin: 'Key of unknown origin',
  private_key_unencrypted: 'Private key without passphrase',
  private_key_bad_permissions: 'Private key readable by others',
  duplicate_key_across_users: 'Key shared across users',
  key_for_disabled_user: 'Key for disabled or missing user',
  permit_root_login_yes: 'Root login with password allowed',
  password_authentication_yes: 'Password login allowed',
  host_key_changed: 'Host key changed',
  known_host_stale: 'Stale known_hosts entry',
  host_unreachable: 'Host not reachable',
  partial_scan: 'Host scanned partially',
  authorized_keys_command: 'AuthorizedKeysCommand not audited',
  cert_authority_trusted: 'Certificate authority trusted',
};
export function ruleTitle(rule: string, f?: { alg?: string | null; bits?: number | null; detail?: any }): string {
  const t = RULES[rule] ?? rule;
  if (!f) return t.replace(' ({alg} {bits})', '').replace('{n} ', 'many ');
  const alg = f.detail?.alg ?? f.alg;
  const bits = f.detail?.bits ?? f.bits;
  return t
    .replace('{alg} {bits}', [algShort(alg), bits].filter(Boolean).join(' ') || 'unknown')
    .replace('{n}', String(f.detail?.hosts ?? '?'));
}
export const ruleTitleGeneric = (rule: string) => ruleTitle(rule);

export function algShort(alg: string | null | undefined): string {
  if (!alg) return '';
  const a = alg.replace('-cert-v01@openssh.com', '');
  if (a === 'ssh-ed25519') return 'ed25519';
  if (a === 'sk-ssh-ed25519@openssh.com') return 'ed25519-sk';
  if (a.startsWith('sk-ecdsa')) return 'ecdsa-sk';
  if (a.startsWith('ecdsa-sha2')) return 'ecdsa';
  if (a === 'ssh-rsa' || a.startsWith('rsa-sha2')) return 'rsa';
  if (a === 'ssh-dss') return 'dsa';
  return a;
}
/** Key-type chip text: "rsa 3072", "ed25519", "dsa 1024". */
export function keyType(alg: string | null | undefined, bits: number | null | undefined): string {
  const a = algShort(alg);
  if (!a) return 'unknown';
  if (a === 'ed25519' || a === 'ed25519-sk' || a === 'ecdsa-sk') return a;
  return bits ? `${a} ${bits}` : a;
}
export const isCert = (alg: string | null | undefined) => !!alg && alg.includes('-cert-');

export const STATUS_LABEL: Record<string, string> = {
  ok: 'OK', partial: 'Partial', unreachable: 'Unreachable', timeout: 'Timeout', auth_failed: 'Auth failed',
  hostkey_mismatch: 'Host key changed', hostkey_unknown: 'Host key unknown', collector_error: 'Collector error',
  output_limit: 'Output limit', excluded: 'Excluded', out_of_scope: 'Out of scope', max_depth: 'Depth limit',
  max_hosts: 'Host limit', unresolvable: 'Unresolvable', alias: 'Alias', already: 'Already found', no_ssh: 'No SSH',
  queued: 'Queued', running: 'Running',
};
export function statusSev(status: string): string {
  if (status === 'ok') return 'low';
  if (status === 'partial') return 'medium';
  if (['unreachable', 'timeout', 'auth_failed', 'collector_error', 'output_limit'].includes(status)) return 'high';
  if (status.startsWith('hostkey_')) return 'critical';
  return 'info';
}
export function statusGlyph(status: string): string {
  const s = statusSev(status);
  return s === 'low' ? 'dot' : s === 'info' ? 'low' : s;
}
export const NOT_SCANNED = ['excluded', 'out_of_scope', 'max_depth', 'max_hosts', 'unresolvable', 'alias', 'already', 'no_ssh'];
export const PRIVILEGE_LABEL: Record<string, string> = { root: 'root', sudo_password: 'sudo password', unprivileged: 'unprivileged' };
export const privilege = (p: string | null | undefined) => (p ? PRIVILEGE_LABEL[p] ?? p : '–');

export const EDGE_STATUS: Record<string, string> = {
  confirmed: 'confirmed', restricted_ok: 'from= ok', restricted_blocked: 'from= blocks', unknown_origin: 'unknown origin',
  known_hosts: 'known_hosts', ssh_config: 'ssh config',
};
export const FLAG_LABEL: Record<string, string> = {
  dst_root: 'root', dst_nologin: 'nologin', dst_user_missing: 'user missing', forced_command: 'command=',
  expired: 'expired', sshd_denied: 'sshd denies',
};
export const SOURCE_LABEL: Record<string, string> = {
  known_hosts: 'known_hosts', known_hosts_hashed: 'known_hosts (hashed)', system_known_hosts: 'system known_hosts',
  ssh_config: 'ssh config', system_ssh_config: 'system ssh config', ssh_config_proxyjump: 'ssh config ProxyJump',
  from_option: 'from= option', entry: 'entry point',
};

export function fileLine(file: string | null | undefined, line: number | null | undefined): string {
  if (!file) return '';
  return line ? `${file}:${line}` : file;
}
/** "/home/…/authorized_keys" style middle truncation for paths. */
export function midTrunc(s: string, max = 40): string {
  if (!s || s.length <= max) return s;
  const keep = max - 1;
  const head = Math.ceil(keep * 0.4), tail = keep - head;
  return s.slice(0, head) + '…' + s.slice(s.length - tail);
}
export function endTrunc(s: string, max = 32): string {
  return !s || s.length <= max ? s : s.slice(0, max - 1) + '…';
}
export function viaText(v: any): string {
  if (!v) return '–';
  if (!v.parent) return v.source === 'entry' ? 'entry point' : v.source ?? '–';
  const tag = v.source === 'known_hosts_hashed' ? ' (hashed)' : '';
  return `${v.parent} ${fileLine(v.file, v.line)}${tag}`;
}
export function scanTitle(s: any): string {
  if (!s) return '';
  return `Scan #${s.id} · ${s.label || 'unlabelled'} · ${fmtTime(s.started_at)}`;
}
export function hostName(name: string | null | undefined, suffix = ''): string {
  if (!name) return '';
  return suffix && name.endsWith(suffix) ? name.slice(0, -suffix.length) : name;
}
