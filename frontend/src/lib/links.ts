import { fpUrl } from './api';

export const hostHref = (scan: number, id: number | null | undefined, tab = '', anchor = '') =>
  id === null || id === undefined ? '' : `/s/${scan}/hosts/${id}${tab ? `?tab=${tab}` : ''}${anchor ? `#${anchor}` : ''}`;
export const keyHref = (scan: number, fp: string | null | undefined) => (fp ? `/s/${scan}/keys/${fpUrl(fp)}` : '');
export const graphHostHref = (scan: number, id: number) => `/s/${scan}/graph?host=${id}`;
export const graphKeyHref = (scan: number, fp: string) => `/s/${scan}/graph?key=${fpUrl(fp)}`;

/** One readable line from a finding's detail JSON. */
export function detailText(f: any): string {
  const d = f.detail ?? {};
  switch (f.rule) {
    case 'key_on_many_hosts':
      return `${d.hosts} hosts (threshold ${d.threshold}): ${(d.host_names ?? []).slice(0, 8).join(', ')}${(d.host_names ?? []).length > 8 ? ', …' : ''}`;
    case 'duplicate_key_across_users':
      return [d.private_holders?.length ? `private half held by ${d.private_holders.join(', ')}` : '',
        d.authorized_for?.length ? `authorized for ${d.authorized_for.join('; ')}` : ''].filter(Boolean).join(' · ');
    case 'key_unknown_origin':
      return d.comment ? `comment "${d.comment}"; no private half on any scanned host` : 'no private half on any scanned host';
    case 'key_for_disabled_user':
      return d.reason ?? '';
    case 'private_key_bad_permissions':
      return (d.problems ?? []).join(', ');
    case 'root_authorized_key':
      return d.from?.length ? `restricted by from="${d.from.join(',')}"` : 'no from= restriction';
    case 'host_key_changed':
      return `stored ${(d.old ?? []).map((o: any) => o.fp).join(', ') || '?'} · presented ${d.new?.fp ?? '?'}`;
    case 'host_unreachable':
      return [d.status, d.error].filter(Boolean).join(': ');
    case 'partial_scan':
      return (d.reasons ?? []).join('; ');
    case 'known_host_stale':
      return d.target ? `key no longer presented by ${d.target}` : '';
    case 'cert_authority_trusted':
      return d.trustedusercakeys ? `TrustedUserCAKeys ${d.trustedusercakeys}` : d.principals ? `principals "${d.principals}"` : 'cert-authority entry';
    case 'authorized_keys_command':
      return d.command ?? '';
    case 'key_strength_critical':
    case 'key_strength_weak':
      return d.where === 'private' ? 'private key file' : 'authorized key';
    default:
      return '';
  }
}
