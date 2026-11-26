<script lang="ts">
  // Host detail (design §4.8, design-revision §5.3).
  import { tick } from 'svelte';
  import { api } from '../lib/api';
  import { route, setQuery } from '../lib/router.svelte';
  import { Resource } from '../lib/state.svelte';
  import { fileLine, midTrunc, n, privilege, SOURCE_LABEL, STATUS_LABEL } from '../lib/format';
  import { graphHostHref, hostHref, keyHref } from '../lib/links';
  import PageHead from '../components/PageHead.svelte';
  import Notices from '../components/Notices.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import StrengthChip from '../components/StrengthChip.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import KeyType from '../components/KeyType.svelte';
  import Fp from '../components/Fp.svelte';
  import HopChain from '../components/HopChain.svelte';
  import OptionChips from '../components/OptionChips.svelte';
  import EdgeTable from '../components/EdgeTable.svelte';
  import FindingsTable from '../components/FindingsTable.svelte';
  import CodeBlock from '../components/CodeBlock.svelte';
  import Strip from '../components/Strip.svelte';
  import Badge from '../components/Badge.svelte';
  import Field from '../components/Field.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import TabBar from '../components/TabBar.svelte';

  let { scan, hostId }: { scan: any; hostId: number } = $props();
  const sid = scan.id;
  const res = new Resource<any>();
  const load = () => res.load(() => api(`/scans/${sid}/hosts/${hostId}`));
  $effect(() => { hostId; load(); });

  const d = $derived(res.data);
  const hs = $derived(d?.host_scan);
  const name = $derived(hs?.display_name ?? '');
  const notScanned = $derived(hs ? ['unreachable', 'timeout', 'auth_failed', 'hostkey_mismatch', 'hostkey_unknown', 'excluded',
    'out_of_scope', 'max_depth', 'max_hosts', 'unresolvable', 'alias', 'no_ssh'].includes(hs.status) : false);
  // Tabs (design §4.8). A host without collected data keeps Overview, Known by and Findings; the data tabs are
  // disabled and then show no count. An unknown or disabled ?tab= falls back to Overview.
  const TAB_KEYS = ['overview', 'users', 'access', 'known_by', 'sshd', 'accounts', 'findings'];
  const DATA_TABS = ['users', 'access', 'sshd', 'accounts'];
  const disabledTab = (t: string) => notScanned && DATA_TABS.includes(t);
  const tab = $derived.by(() => {
    const t = route.query.get('tab') ?? 'overview';
    return TAB_KEYS.includes(t) && !disabledTab(t) ? t : 'overview';
  });
  let accessLayer = $state<'access' | 'evidence'>('access');
  let showAllAccounts = $state(false);

  const accIn = $derived((d?.edges_in ?? []).filter((e: any) => e.kind === 'access'));
  const accOut = $derived((d?.edges_out ?? []).filter((e: any) => e.kind === 'access'));
  const evIn = $derived((d?.edges_in ?? []).filter((e: any) => e.kind === 'evidence'));
  const evOut = $derived((d?.edges_out ?? []).filter((e: any) => e.kind === 'evidence'));
  const accounts = $derived(new Map((d?.accounts ?? []).map((a: any) => [a.username, a])));
  const sshUsers = $derived(new Set((d?.users ?? []).map((u: any) => u.username)));
  const hostIds = $derived.by(() => {
    const m: Record<string, number> = {};
    for (const e of [...(d?.edges_in ?? []), ...(d?.edges_out ?? [])]) {
      if (e.src) m[e.src] = e.src_host_id;
      if (e.dst) m[e.dst] = e.dst_host_id;
    }
    if (hs?.discovered_via?.parent) m[hs.discovered_via.parent] = hs.discovered_via.parent_host_id;
    if (hs) m[name] = hostId;
    return m;
  });
  const hkFinding = $derived((d?.findings ?? []).find((f: any) => f.rule === 'host_key_changed'));
  const stale = $derived((d?.known_by ?? []).filter((k: any) => k.matches_actual === 'no').length);

  const PINNED = ['permitrootlogin', 'passwordauthentication', 'pubkeyauthentication', 'authorizedkeysfile', 'trustedusercakeys'];
  const SECOND = ['allowusers', 'allowgroups', 'denyusers', 'denygroups'];
  const NICE: Record<string, string> = { permitrootlogin: 'PermitRootLogin', passwordauthentication: 'PasswordAuthentication',
    pubkeyauthentication: 'PubkeyAuthentication', authorizedkeysfile: 'AuthorizedKeysFile', trustedusercakeys: 'TrustedUserCAKeys',
    allowusers: 'AllowUsers', allowgroups: 'AllowGroups', denyusers: 'DenyUsers', denygroups: 'DenyGroups',
    authorizedkeyscommand: 'AuthorizedKeysCommand', kbdinteractiveauthentication: 'KbdInteractiveAuthentication' };
  function risk(nm: string, v: string): string | null {
    if (nm === 'permitrootlogin' && v === 'yes') return 'high';
    if (nm === 'passwordauthentication' && v === 'yes') return 'medium';
    if (nm === 'trustedusercakeys' && v && v !== 'none') return 'info';
    if (nm === 'authorizedkeyscommand' && v && v !== 'none') return 'info';
    return null;
  }
  const sshd = $derived.by(() => {
    const rows = (d?.sshd ?? []) as any[];
    const eff = rows.filter((r) => r.source === 'sshd-T' && r.name !== 'match');
    const base = eff.length ? eff : rows.filter((r) => r.name !== 'match');
    const parsed = new Map(rows.filter((r) => r.source === 'parsed').map((r) => [r.name, r]));
    const withSrc = base.map((r) => ({ ...r, file: r.file ?? parsed.get(r.name)?.file, line: r.line ?? parsed.get(r.name)?.line }));
    const pin = PINNED.map((k) => withSrc.find((r) => r.name === k)).filter(Boolean);
    const sec = SECOND.flatMap((k) => withSrc.filter((r) => r.name === k));
    const rest = withSrc.filter((r) => !PINNED.includes(r.name) && !SECOND.includes(r.name));
    return { pin, sec, rest, match: rows.filter((r) => r.name === 'match') };
  });
  let showAllSshd = $state(false);

  function setTab(t: string) { setQuery({ tab: t === 'overview' ? null : t }, true); }
  const shownAccounts = $derived((d?.accounts ?? []).filter((a: any) => showAllAccounts || sshUsers.has(a.username)));
  const tabs = $derived.by(() => {
    if (!d) return [];
    const acc = shownAccounts.length === d.accounts.length ? `${d.accounts.length}` : `${shownAccounts.length} of ${d.accounts.length}`;
    const all: [string, string, string][] = [
      ['overview', 'Overview', ''], ['users', 'Users', `${d.users.length}`],
      ['access', 'Access', `${accIn.length} in, ${accOut.length} out`], ['known_by', 'Known by', `${d.known_by.length}`],
      ['sshd', 'sshd', ''], ['accounts', 'Accounts', acc], ['findings', 'Findings', `${d.findings.length}`]];
    return all.map(([k, l, c]) => ({ key: k, label: l, count: c && !disabledTab(k) ? `(${c})` : '', disabled: disabledTab(k) }));
  });
  // Route attempts with an error: shown under the status line for every host that has one, also when a later
  // route worked (c1: jump → c1 failed, jump → b3 → c1 ok). Unreachable hosts show them in their strip.
  const UNREACHED = ['unreachable', 'timeout', 'auth_failed'];
  const attempts = $derived((hs?.route_attempts ?? []) as any[]);
  const showAttempts = $derived(!!hs && !UNREACHED.includes(hs.status) && attempts.some((a) => a.error));
  const names = $derived(d ? d.names.filter((x: any) => x.kind === 'name').map((x: any) => x.value) : []);
  const addrs = $derived(hs ? [...new Set([...(hs.ips ?? []), ...(d?.names ?? []).filter((x: any) => x.kind === 'ip').map((x: any) => x.value)])].filter(Boolean) as string[] : []);

  // scroll to #user-x / #finding-n once loaded
  let target = $state('');
  $effect(() => {
    if (!d) return;
    const h = decodeURIComponent(location.hash.slice(1));
    if (!h) return;
    target = h;
    tick().then(() => document.getElementById(h)?.scrollIntoView({ block: 'start' }));
  });
  let exportOpen = $state(false);
  const unmatchedFor = (u: string) => (d?.known_hosts ?? []).filter((k: any) => k.username === u && k.hashed && !k.target_host_id && !k.resolved_value).length;
  function userChips(u: string): string[] {
    if (!u) return [];
    const a: any = accounts.get(u);
    if (!a) return d?.accounts?.length ? ['missing'] : [];
    const c: string[] = [];
    if (!a.login_shell) c.push('nologin');
    if (a.pw_state === 'locked') c.push('locked');
    return c;
  }
</script>

<svelte:window onclick={(e) => { if (!(e.target as HTMLElement).closest('.exp')) exportOpen = false; }} />

{#snippet attemptsTable(list: any[], label: string)}
  <table class="t att" aria-label={label}>
    <thead><tr><th>Route</th><th>Error</th></tr></thead>
    <tbody>
      {#each list as a}<tr><td class="nowrap"><HopChain route={a.route} links={hostIds} scan={sid} /></td>
        <td>{#if a.error}<span class="mono err" title={a.error}>{a.error}</span>{:else}<span class="state">ok</span>{/if}</td></tr>
      {:else}<tr><td colspan="2" class="mono">{hs.error ?? 'no route was tried'}</td></tr>{/each}
    </tbody>
  </table>
{/snippet}

{#if res.error}
  <PageHead title="Host" />
  <ErrorPanel thing="host {hostId}" message={res.error} retry={res.errorCode === 'host_not_found' ? undefined : load} />
{:else if !d}
  {#if res.slow}<Skeleton />{/if}
{:else}
  <PageHead title={name}>
    {#snippet badge()}<StatusBadge status={hs.status} />{/snippet}
    {#snippet sub()}
      <div class="line">
        <span class="pv"><span class="muted">discovered via</span>
          {#if hs.discovered_via?.parent}<a class="plain" href={hostHref(sid, hs.discovered_via.parent_host_id)}>{hs.discovered_via.parent}</a> <span class="mono path">{fileLine(hs.discovered_via.file, hs.discovered_via.line)}</span>{#if hs.discovered_via.source === 'known_hosts_hashed'} <span class="secondary">(hashed)</span>{/if}
          {:else}<span class="primary">{SOURCE_LABEL[hs.discovered_via?.source] ?? hs.discovered_via?.source ?? '–'}</span>{/if}</span>
        {#if hs.route}<span class="pv"><span class="muted">route</span> <HopChain route={hs.route} links={hostIds} scan={sid} /></span>{/if}
      </div>
    {/snippet}
    {#snippet fields()}
      <Field label="Privilege" value={privilege(hs.privilege)} />
      <Field label="Depth" value={hs.depth ?? '–'} />
      <Field label="Addresses" title={addrs.join(', ')}>{#if addrs.length}<span class="num">{addrs[0]}</span>{#if addrs.length > 1}<span class="muted"> +{addrs.length - 1}</span>{/if}{:else}<span class="num">{hs.connect_addr}</span>{/if}</Field>
      <Field label="OS" value={hs.os ?? '–'} />
      <Field label="Kernel" value={hs.kernel ?? '–'} />
    {/snippet}
    {#snippet actions()}
      <a class="btn" href={graphHostHref(sid, hostId)}>Show in graph</a>
      <div class="exp">
        <button class="btn" aria-haspopup="menu" aria-expanded={exportOpen} onclick={() => (exportOpen = !exportOpen)}>Export findings<svg class="chev" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M3 4.5 6 7.5 9 4.5" fill="none" stroke="currentColor" stroke-width="1.5" /></svg></button>
        {#if exportOpen}<div class="popover expmenu" role="menu">
          <a role="menuitem" href="/api/scans/{sid}/export/findings.csv?host_id={hostId}" download>Findings (CSV)</a>
          <a role="menuitem" href="/api/scans/{sid}/export/findings.json?host_id={hostId}" download>Findings (JSON)</a>
        </div>{/if}
      </div>
    {/snippet}
  </PageHead>
  <Notices {scan} />

  {#if showAttempts}
    <section class="panel flush attempts">
      <header><h2 class="section-title">Route attempts</h2></header>
      {@render attemptsTable(attempts, 'Route attempts')}
    </section>
  {/if}

  {#if hs.status === 'partial' || hs.status === 'output_limit'}
    <Strip role="warning">
      <span>Scanned partially:</span>
      <ul class="reasons">{#each hs.partial_reasons as r}<li>{r}</li>{:else}<li>{hs.error ?? hs.status}</li>{/each}</ul>
      <span class="secondary">Rerun with <span class="mono">--ask-sudo-password</span> or grant sudo to the audit account.</span>
    </Strip>
  {:else if UNREACHED.includes(hs.status)}
    <Strip role="high">
      <p class="st">Not scanned: {STATUS_LABEL[hs.status].toLowerCase()}.</p>
      <div class="inner">{@render attemptsTable(hs.route_attempts ?? [], 'Route attempts')}</div>
    </Strip>
  {:else if hs.status === 'hostkey_mismatch' || hs.status === 'hostkey_unknown'}
    <Strip role="error">
      <p class="st">{hs.status === 'hostkey_mismatch' ? 'Host key changed – not scanned.' : 'Host key unknown – not scanned.'}</p>
      {#if hkFinding}
        <dl class="hk">
          {#each hkFinding.detail.old ?? [] as o}<div><dt>Stored <span class="muted">{o.alg}</span></dt><dd><Fp fp={o.fp} full size={13} /></dd></div>{/each}
          {#if hkFinding.detail.new}<div><dt>Presented <span class="muted">{hkFinding.detail.new.alg}</span></dt><dd><Fp fp={hkFinding.detail.new.fp} full size={13} /></dd></div>{/if}
        </dl>
      {:else if hs.error}<p class="mono dense">{hs.error}</p>{/if}
      <p class="vf">Verify out-of-band, then run:</p>
      <CodeBlock cmd="sshbite hostkey accept {hs.connect_addr}{hs.connect_port && hs.connect_port !== 22 ? ':' + hs.connect_port : ''}" />
    </Strip>
  {:else if hs.status === 'collector_error'}
    <Strip role="high">
      <p class="st">Collector error:</p>
      <p class="mono dense wrap" data-testid="collector-error">{hs.error ?? 'no message'}</p>
    </Strip>
  {/if}

  <TabBar sticky selected={tab}>
    {#each tabs as t (t.key)}
      <button role="tab" aria-selected={tab === t.key} disabled={t.disabled} title={t.disabled ? 'No data: host was not scanned.' : ''} onclick={() => setTab(t.key)}><span>{t.label}{#if t.count}{' '}<span class="cnt">{t.count}</span>{/if}</span></button>
    {/each}
  </TabBar>

  <section class="tabpanel" role="tabpanel">
    {#if tab === 'overview'}
      <div class="ov">
        <section class="panel">
          <h2 class="section-title ptitle">Host</h2>
          <dl class="dl">
            <dt>Names</dt><dd>{names.join(', ') || '–'}</dd>
            <dt>IPs</dt><dd class="num">{addrs.join(', ') || '–'}</dd>
            <dt>Connected at</dt><dd class="num">{hs.connect_addr}{hs.connect_port && hs.connect_port !== 22 ? ':' + hs.connect_port : ''}</dd>
            <dt>OS</dt><dd>{hs.os ?? '–'}</dd>
            <dt>Kernel</dt><dd>{hs.kernel ?? '–'}</dd>
            <dt>Groups</dt><dd>{#each Object.entries(d.groups) as [k, v]}<div><span class="muted">{k}</span> {v}</div>{:else}–{/each}</dd>
            <dt>Scan time</dt><dd class="num">{hs.duration_ms !== null ? `${(hs.duration_ms / 1000).toFixed(1)} s` : '–'}</dd>
          </dl>
          <h3 class="sub-title">Host keys</h3>
          {#if d.host_keys.length}
            <table class="t hkt">
              <thead><tr><th>Algorithm</th><th>Fingerprint</th></tr></thead>
              <tbody>{#each d.host_keys as k}<tr><td><KeyType alg={k.alg} bits={k.bits} /></td>
                <td><span class="fpshort"><Fp fp={k.fp} /></span><span class="fpfull"><Fp fp={k.fp} full /></span></td></tr>{/each}</tbody>
            </table>
          {:else}<p class="secondary dense">No host key was collected.</p>{/if}
        </section>
        <section class="panel">
          <h2 class="section-title ptitle">Access counts</h2>
          <dl class="dl num">
            <dt>In: hosts / users / keys</dt><dd>{d.metrics.in_hosts} / {d.metrics.in_users} / {d.metrics.in_keys}</dd>
            <dt>Unknown-origin keys</dt><dd>{d.metrics.in_unknown_keys}</dd>
            <dt>Out: hosts / users / keys</dt><dd>{d.metrics.out_hosts} / {d.metrics.out_users} / {d.metrics.out_keys}</dd>
            <dt>Evidence in / out</dt><dd>{d.metrics.ev_in_hosts} / {d.metrics.ev_out_hosts}</dd>
            <dt>Unmatched hashed known_hosts</dt><dd>{d.unresolved_hashed}</dd>
          </dl>
          <p class="meta muted cnote">Counts only effective access edges between different hosts.</p>
        </section>
      </div>

    {:else if tab === 'users'}
      {#if d.users.length === 0}
        <p class="emptytab">No user on {name} has SSH files.</p>
      {/if}
      {#each d.users as u (u.username)}
        {@const acc = accounts.get(u.username) as any}
        {@const auth = d.authorized.filter((a: any) => a.username === u.username)}
        {@const priv = d.private_keys.filter((p: any) => p.username === u.username)}
        {@const kh = d.known_hosts.filter((k: any) => k.username === u.username)}
        {@const cfg = d.ssh_config.filter((c: any) => c.username === u.username)}
        <section class="panel flush user" id="user-{u.username}" class:target={target === `user-${u.username}`}>
          <div class="uh">
            <h2 class="section-title">{u.username || '(system files)'}</h2>
            {#if acc}<dl class="ctx"><Field label="uid" value={acc.uid} /><Field label="Shell" value={acc.shell || 'no shell'} /></dl>{/if}
            <span class="chips">{#each userChips(u.username) as c}{#if c === 'missing'}<Badge role="medium" label="missing" />{:else}<span class="kchip">{c}</span>{/if}{/each}</span>
          </div>
          {#if auth.length}
            <h3 class="sub-title sect">Authorized keys</h3>
            <div class="table-wrap"><table class="t ut">
              {@render cols(COLS.auth)}
              <thead><tr><th>File:line</th><th>Strength</th><th>Type</th><th>Fingerprint</th><th>Comment</th><th>Options</th><th>Origin</th></tr></thead>
              <tbody>{#each auth as a (a.id)}<tr>
                <td class="mono" title={fileLine(a.file, a.line)}>{midTrunc(fileLine(a.file, a.line), FL)}</td>
                <td><StrengthChip strength={a.strength} /></td>
                <td><KeyType alg={a.alg} bits={a.bits} /></td>
                <td><Fp fp={a.fp} href={keyHref(sid, a.fp)} /></td>
                <td><div class="clamp2" title={a.comment ?? ''}>{a.comment ?? '–'}</div>{#if a.label}<div class="meta secondary clamp2" title={a.label}>“{a.label}”</div>{/if}</td>
                <td class="optc"><OptionChips options={a.options} /></td>
                <td>{#if a.origin === 'ca'}<span class="kchip">CA trusted</span>
                  {:else if a.origin === 'known'}<a class="plain" href={keyHref(sid, a.fp)}>Known private holder ({a.holders})</a>
                  {:else}<span class="state unknown">Unknown origin</span>{/if}</td>
              </tr>{/each}</tbody>
            </table></div>
          {/if}
          {#if priv.length}
            <h3 class="sub-title sect">Private keys</h3>
            <div class="table-wrap"><table class="t ut">
              {@render cols(COLS.priv)}
              <thead><tr><th>Path</th><th>Strength</th><th>Type</th><th>Fingerprint</th><th>Encrypted</th><th>Mode</th><th>Owner</th></tr></thead>
              <tbody>{#each priv as p (p.id)}<tr>
                <td class="mono" title={p.path}>{midTrunc(p.path, FL)}</td>
                <td><StrengthChip strength={p.strength} /></td>
                <td><KeyType alg={p.alg} bits={p.bits} /></td>
                <td><Fp fp={p.fp} href={keyHref(sid, p.fp)} /></td>
                <td>{#if p.encrypted === 'no'}<Badge role="medium" label="no" />{:else}{p.encrypted}{/if}</td>
                <td>{#if p.mode_bad}<Badge role="high" label={p.mode} />{:else}<span class="mono">{p.mode ?? '–'}</span>{/if}</td>
                <td class="wrap-any">{p.owner ?? '–'}</td>
              </tr>{/each}</tbody>
            </table></div>
          {/if}
          {#if kh.length}
            <h3 class="sub-title sect">known_hosts</h3>
            {#if unmatchedFor(u.username) > 0}<p class="dense secondary padx">{plural2(unmatchedFor(u.username))} could not be matched.</p>{/if}
            <div class="table-wrap"><table class="t ut">
              {@render cols(COLS.kh)}
              <thead><tr><th>File:line</th><th>Pattern</th><th>Resolved host</th><th>Key</th><th>Match</th></tr></thead>
              <tbody>{#each kh as k (k.id)}<tr>
                <td class="mono" title={fileLine(k.file, k.line)}>{midTrunc(fileLine(k.file, k.line), FL)}</td>
                <td class="wrap-any">{#if k.hashed}<span class="muted">hashed</span>{#if k.resolved_value}{' = ' + k.resolved_value}{/if}{:else}{k.patterns.join(',')}{/if}{#if k.marker} <span class="kchip">{k.marker}</span>{/if}</td>
                <td>{#if k.target_host_id}<a class="plain" href={hostHref(sid, k.target_host_id)}>{k.target}</a>{:else}<span class="muted">–</span>{/if}</td>
                <td><span class="kr"><KeyType alg={k.key_alg} /><Fp fp={k.key_fp} /></span></td>
                <td>{#if k.matches_actual === 'yes'}<span class="state">matches</span>{:else if k.matches_actual === 'no'}<Badge role="low" label="stale" />{:else}<span class="state muted">unknown</span>{/if}</td>
              </tr>{/each}</tbody>
            </table></div>
          {/if}
          {#if cfg.length}
            <h3 class="sub-title sect">ssh config</h3>
            <div class="table-wrap"><table class="t ut">
              {@render cols(COLS.cfg)}
              <thead><tr><th>File:line</th><th>Host</th><th>HostName</th><th>User</th><th>Port</th><th>IdentityFile</th><th>ProxyJump</th></tr></thead>
              <tbody>{#each cfg as c}<tr>
                <td class="mono" title={fileLine(c.file, c.line)}>{midTrunc(fileLine(c.file, c.line), FL)}</td>
                <td class="wrap-any">{c.host_pattern ?? '–'}</td><td class="wrap-any">{c.hostname ?? '–'}</td><td class="wrap-any">{c.user ?? '–'}</td>
                <td class="num">{c.port ?? '–'}</td><td class="wrap-any" class:mono={c.identity_files.length > 0}>{c.identity_files.join(', ') || '–'}</td><td class="wrap-any">{c.proxyjump ?? '–'}</td>
              </tr>{/each}</tbody>
            </table></div>
          {/if}
        </section>
      {/each}

    {:else if tab === 'access'}
      <div class="row"><div class="seg" role="radiogroup" aria-label="Layer">
        <button role="radio" aria-checked={accessLayer === 'access'} onclick={() => (accessLayer = 'access')}>Access</button>
        <button role="radio" aria-checked={accessLayer === 'evidence'} onclick={() => (accessLayer = 'evidence')}>Evidence</button>
      </div>{#if accessLayer === 'evidence'}<span class="meta secondary">Evidence – known_hosts and ssh config references, not access</span>{/if}</div>
      <section class="panel flush">
        <header><h2 class="section-title">Who can log in here</h2></header>
        {#if accessLayer === 'access'}<EdgeTable edges={accIn} scan={sid} show="both" empty="No one can log in to {name} with a key." />
        {:else}<EdgeTable edges={evIn} scan={sid} evidence empty="No known_hosts or ssh config entry on another scanned host points to {name}." />{/if}
      </section>
      <section class="panel flush">
        <header><h2 class="section-title">Where this host can log in</h2></header>
        {#if accessLayer === 'access'}<EdgeTable edges={accOut} scan={sid} show="both" empty="No key on {name} opens another scanned host." />
        {:else}<EdgeTable edges={evOut} scan={sid} evidence empty="No known_hosts or ssh config entry on {name} points to a scanned host." />{/if}
      </section>

    {:else if tab === 'known_by'}
      <section class="panel flush">
        {#if stale}<header><p class="dense secondary">{stale} of {d.known_by.length} entries are stale.</p></header>{/if}
        <div class="table-wrap"><table class="t">
          <thead><tr><th>Host</th><th>User</th><th>File:line</th><th>Key</th><th>Match</th></tr></thead>
          <tbody>
            {#each d.known_by as k (k.id)}
              <tr>
                <td class="ent"><a href={hostHref(sid, k.host_id)}>{k.host}</a></td>
                <td>{k.username || '(system)'}</td>
                <td class="mono" title={fileLine(k.file, k.line)}>{midTrunc(fileLine(k.file, k.line), 40)}{#if k.hashed} <span class="muted sans">(hashed)</span>{/if}</td>
                <td><span class="kr"><KeyType alg={k.key_alg} /><Fp fp={k.key_fp} /></span></td>
                <td>{#if k.matches_actual === 'yes'}<span class="state">matches</span>{:else if k.matches_actual === 'no'}<Badge role="low" label="Stale – key no longer presented" />{:else}<span class="state muted">unknown</span>{/if}</td>
              </tr>
            {:else}<tr><td class="empty" colspan="5">No scanned host has {name} in its known_hosts.</td></tr>{/each}
          </tbody>
        </table></div>
      </section>

    {:else if tab === 'sshd'}
      <section class="panel flush">
        <div class="table-wrap"><table class="t">
          <thead><tr><th>Setting</th><th>Value</th><th>Source</th><th>File:line</th></tr></thead>
          <tbody>
            {#each [...sshd.pin, ...sshd.sec] as r}
              {@const rk = risk(r.name, r.value)}
              <tr class="pinned"><td class="sname">{NICE[r.name] ?? r.name}</td><td class="wrap-any"><span class="vrow"><span class:mono={isPathy(r.value)}>{r.value}</span>{#if rk}<SevBadge severity={rk} />{/if}</span></td><td class="secondary">{r.source}</td>{@render fl(r)}</tr>
            {/each}
            {#each showAllSshd ? sshd.rest : [] as r}
              <tr><td>{NICE[r.name] ?? r.name}</td><td class="wrap-any" class:mono={isPathy(r.value)}>{r.value}</td><td class="secondary">{r.source}</td>{@render fl(r)}</tr>
            {/each}
            {#if !sshd.pin.length && !sshd.rest.length}<tr><td class="empty" colspan="4">No sshd settings were read on {name}.</td></tr>{/if}
          </tbody>
        </table></div>
        {#if sshd.rest.length}<div class="tfoot"><button class="btn ghost small" onclick={() => (showAllSshd = !showAllSshd)}>{showAllSshd ? 'Show the relevant settings only' : `Show all ${n(sshd.rest.length + sshd.pin.length + sshd.sec.length)} settings`}</button></div>{/if}
      </section>
      {#each sshd.match as m}
        <section class="panel"><h3 class="section-title mtitle">Match block (shown as written; not evaluated)</h3><pre class="raw">{m.value}</pre>
          {#if m.file}<p class="meta mono secondary mfile">{fileLine(m.file, m.line)}</p>{/if}</section>
      {/each}

    {:else if tab === 'accounts'}
      <div class="row"><label class="check"><input type="checkbox" bind:checked={showAllAccounts} />Show all accounts</label>
        {#if !showAllAccounts}<span class="meta secondary">Only accounts with SSH data</span>{/if}</div>
      <section class="panel flush">
        <div class="table-wrap"><table class="t">
          <thead><tr><th>Username</th><th class="r">UID</th><th>Shell</th><th>Login shell</th><th>Password</th><th>Expiry</th></tr></thead>
          <tbody>
            {#each shownAccounts as a (a.username)}
              <tr><td class="ent">{#if sshUsers.has(a.username)}<a href="?tab=users#user-{encodeURIComponent(a.username)}">{a.username}</a>{:else}{a.username}{/if}</td><td class="r num">{a.uid}</td><td class:mono={!!a.shell}>{a.shell || '–'}</td>
                <td>{a.login_shell ? 'yes' : 'no'}</td><td>{a.pw_state}</td><td class="num">{a.expiry ?? '–'}</td></tr>
            {:else}<tr><td class="empty" colspan="6">{d.accounts.length ? 'No account on this host has SSH data.' : `No accounts were read on ${name}.`}</td></tr>{/each}
          </tbody>
        </table></div>
      </section>

    {:else if tab === 'findings'}
      <section class="panel flush">
        <FindingsTable items={d.findings} scan={sid} {target} empty="No findings for {name} in scan #{sid}." />
      </section>
    {/if}
  </section>
{/if}

{#snippet cols(w: number[])}<colgroup>{#each w as x}<col style:width="{x}%" />{/each}</colgroup>{/snippet}
{#snippet fl(r: any)}<td class:mono={!!fileLine(r.file, r.line)}>{fileLine(r.file, r.line) || '–'}</td>{/snippet}

<script lang="ts" module>
  // Mono only for paths, commands and raw values (design-revision §3.4); yes / no / none / numbers stay Sans
  // Users tab (check-12 F2): one fixed column grid per table kind, the same in every user panel of a host, so
  // Strength, Type and Fingerprint line up from panel to panel. File:line is always the first 23.5 %.
  const COLS = {
    auth: [23.5, 9, 8.8, 15.6, 10, 15.8, 17.3],    // File:line, Strength, Type, Fingerprint, Comment, Options, Origin
    priv: [23.5, 9, 8.8, 15.6, 13, 13, 17.1],    // Path, Strength, Type, Fingerprint, Encrypted, Mode, Owner
    kh: [23.5, 20, 17, 23.5, 16],             // File:line, Pattern, Resolved host, Key, Match
    cfg: [23.5, 12.5, 15.5, 10, 7.5, 17.5, 13.5],     // File:line, Host, HostName, User, Port, IdentityFile, ProxyJump
  };
  const FL = 28;   // characters of File:line / Path before the middle is cut (full value in the title)
  function isPathy(v: string | null | undefined) { return !!v && /[\/%~=@"]/.test(v); }
  function plural2(v: number) { return v === 1 ? '1 hashed entry' : `${v} hashed entries`; }
</script>
<style>
  .chev { color: var(--text-muted); }
  .line { display: flex; flex-wrap: wrap; align-items: baseline; gap: var(--s2) var(--s6); font-size: 13px; line-height: 20px; color: var(--text-primary); }
  .pv { display: inline-flex; align-items: baseline; gap: .35em; flex-wrap: wrap; }
  .path { font-size: 12px; color: var(--text-secondary); }
  .primary { color: var(--text-primary); }
  .reasons { margin: var(--s2) 0; padding-left: var(--s5); }
  /* Route attempts: its own section, 16 px above and below (the page gap) */
  .att .err { font-size: 12px; }
  .st { font-weight: 500; }
  .wrap { overflow-wrap: anywhere; }
  .inner { margin-top: var(--s3); background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--r2);
    overflow: hidden; max-width: 720px; }
  .hk { display: flex; flex-direction: column; gap: var(--s3); margin: var(--s3) 0; }
  .hk dt { font-size: 12px; line-height: 16px; color: var(--text-secondary); font-weight: 500; }
  .hk dd { margin: 0; }
  .vf { margin-bottom: var(--s2); }
  :global(.strip .code) { background: var(--bg-surface); max-width: 560px; }
  /* tabs: sticky under the top bar */
  .tabpanel { display: flex; flex-direction: column; gap: var(--s5); }
  .ov { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr); gap: var(--s5); align-items: start; }
  .ptitle { margin-bottom: var(--s4); }
  .sub-title { font-size: 14px; line-height: 20px; font-weight: 600; margin: var(--s5) 0 var(--s3); }
  .hkt { margin-top: var(--s2); border: 1px solid var(--border-subtle); border-radius: var(--r2); }
  .hkt :global(th:first-child), .hkt :global(td:first-child) { padding-left: var(--s4); width: 120px; }
  .fpfull { display: none; }
  .cnote { margin-top: var(--s4); }
  .user { scroll-margin-top: 120px; }
  .user.target { border-color: var(--accent); }
  .uh { display: flex; gap: var(--s6); align-items: center; flex-wrap: wrap; padding: var(--s4) var(--s5); }
  .user .sub-title.sect { margin: 0; padding: var(--s4) var(--s5) var(--s3); border-top: 1px solid var(--border-subtle); }
  .padx { padding: 0 var(--s5) var(--s3); }
  /* fixed column grid of the Users tab; below 880 px the table scrolls inside its panel */
  .ut { table-layout: fixed; min-width: 880px; }
  .ut :global(td) { overflow: hidden; }
  .ut :global(th:not(:first-child)), .ut :global(td:not(:first-child)) { padding-left: var(--s3); }
  .ut :global(th:not(:last-child)), .ut :global(td:not(:last-child)) { padding-right: var(--s3); }
  .ut :global(td.mono) { white-space: nowrap; text-overflow: ellipsis; }
  .clamp2 { display: -webkit-box; -webkit-line-clamp: 2; line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; overflow-wrap: anywhere; }
  .optc :global(.chips) { max-width: 100%; }
  .optc :global(.kchip.opt) { max-width: 100%; height: auto; min-height: 20px; white-space: normal; overflow-wrap: anywhere; }
  .kr { display: inline-flex; gap: var(--s3); align-items: center; white-space: nowrap; }
  .vrow { display: inline-flex; gap: var(--s3); align-items: center; flex-wrap: wrap; }
  .sname { font-weight: 500; }
  .mtitle { margin-bottom: var(--s3); }
  .mfile { margin-top: var(--s2); }
  .emptytab { padding: var(--s7) 0; color: var(--text-secondary); }
  :global(tr[id^='finding-']) { scroll-margin-top: 120px; }
  @media (max-width: 1100px) { .ov { grid-template-columns: minmax(0, 1fr); } }
  /* below 640 px the host keys show the full form in groups of 4, breaking only between groups */
  @media (max-width: 639px) { .fpshort { display: none; } .fpfull { display: inline; } .hkt :global(td:first-child) { width: auto; } }
</style>
