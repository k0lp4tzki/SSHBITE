<script lang="ts">
  // Host detail (design §4.8).
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
  import Glyph from '../components/Glyph.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';
  import Skeleton from '../components/Skeleton.svelte';

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
  const tab = $derived(route.query.get('tab') ?? 'overview');
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
  const disabledTab = (t: string) => notScanned && !['overview', 'known_by'].includes(t);

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

{#if res.error}
  <PageHead title="Host" />
  <ErrorPanel thing="host {hostId}" message={res.error} retry={res.errorCode === 'host_not_found' ? undefined : load} />
{:else if !d}
  {#if res.slow}<Skeleton />{/if}
{:else}
  <div class="head">
    <PageHead title={name} mono>
      {#snippet sub()}
        <div class="line"><StatusBadge status={hs.status} />{#if hs.privilege}{' · ' + privilege(hs.privilege)}{/if} · depth {hs.depth ?? '–'} · discovered via
          {#if hs.discovered_via?.parent}<a class="mono" href={hostHref(sid, hs.discovered_via.parent_host_id)}>{hs.discovered_via.parent}</a> <span class="mono">{fileLine(hs.discovered_via.file, hs.discovered_via.line)}</span>{#if hs.discovered_via.source === 'known_hosts_hashed'} (hashed){/if}
          {:else}<span>{SOURCE_LABEL[hs.discovered_via?.source] ?? hs.discovered_via?.source ?? '–'}</span>{/if}
          {#if hs.route}{' · route '}<HopChain route={hs.route} links={hostIds} scan={sid} />{/if}
        </div>
        <div class="line mono secondary">{[...d.names.filter((x: any) => x.kind === 'name').map((x: any) => x.value), ...hs.ips].filter((v, i, a) => a.indexOf(v) === i).join(' · ') || hs.connect_addr}{#if hs.os}{' · '}<span class="sans">{hs.os}</span>{/if}{#if hs.kernel}{' · ' + hs.kernel}{/if}</div>
      {/snippet}
      {#snippet actions()}
        <a class="btn" href={graphHostHref(sid, hostId)}>Show in graph</a>
        <div class="exp">
          <button class="btn" aria-haspopup="menu" aria-expanded={exportOpen} onclick={() => (exportOpen = !exportOpen)}>Export findings ▾</button>
          {#if exportOpen}<div class="popover expmenu" role="menu">
            <a role="menuitem" href="/api/scans/{sid}/export/findings.csv?host_id={hostId}" download>Findings (CSV)</a>
            <a role="menuitem" href="/api/scans/{sid}/export/findings.json?host_id={hostId}" download>Findings (JSON)</a>
          </div>{/if}
        </div>
      {/snippet}
    </PageHead>
    <Notices {scan} />

    {#if hs.status === 'partial' || hs.status === 'output_limit'}
      <Strip role="warning">
        <span>Scanned partially:</span>
        <ul class="reasons mono">{#each hs.partial_reasons as r}<li>{r}</li>{:else}<li>{hs.error ?? hs.status}</li>{/each}</ul>
        <span class="secondary">Rerun with <span class="mono">--ask-sudo-password</span> or grant sudo to the audit account.</span>
      </Strip>
    {:else if ['unreachable', 'timeout', 'auth_failed'].includes(hs.status)}
      <Strip role="high">
        <span>Not scanned: {STATUS_LABEL[hs.status].toLowerCase()}.</span>
        <table class="t att"><thead><tr><th>Route</th><th>Error</th></tr></thead><tbody>
          {#each hs.route_attempts as a}<tr><td><HopChain route={a.route} links={hostIds} scan={sid} /></td><td class="mono">{a.error ?? 'ok'}</td></tr>{:else}<tr><td colspan="2" class="mono">{hs.error ?? 'no route was tried'}</td></tr>{/each}
        </tbody></table>
      </Strip>
    {:else if hs.status === 'hostkey_mismatch' || hs.status === 'hostkey_unknown'}
      <Strip role="error">
        <span>{hs.status === 'hostkey_mismatch' ? 'Host key changed – not scanned.' : 'Host key unknown – not scanned.'}</span>
        {#if hkFinding}
          <dl class="dl hk">
            {#each hkFinding.detail.old ?? [] as o}<dt>Stored ({o.alg})</dt><dd><Fp fp={o.fp} full /></dd>{/each}
            {#if hkFinding.detail.new}<dt>Presented ({hkFinding.detail.new.alg})</dt><dd><Fp fp={hkFinding.detail.new.fp} full /></dd>{/if}
          </dl>
        {:else if hs.error}<p class="mono dense">{hs.error}</p>{/if}
        <p>Verify out-of-band, then run:</p>
        <CodeBlock cmd="sshbite hostkey accept {hs.connect_addr}{hs.connect_port && hs.connect_port !== 22 ? ':' + hs.connect_port : ''}" />
      </Strip>
    {/if}

    <div class="tabs" role="tablist">
      {#each [['overview', 'Overview'], ['users', `Users (${d.users.length})`], ['access', `Access (${accIn.length} in · ${accOut.length} out)`], ['known_by', `Known by (${d.known_by.length})`], ['sshd', 'sshd'], ['accounts', `Accounts (${d.accounts.length})`], ['findings', `Findings (${d.findings.length})`]] as [k, l]}
        <button role="tab" aria-selected={tab === k} disabled={disabledTab(k)} title={disabledTab(k) ? 'No data: host was not scanned.' : ''} onclick={() => setTab(k)}>{l}</button>
      {/each}
    </div>
  </div>

  <section class="tabpanel" role="tabpanel">
    {#if tab === 'overview' || disabledTab(tab)}
      <div class="ov">
        <section class="panel">
          <h2 class="section-title">Host</h2>
          <dl class="dl">
            <dt>Names</dt><dd class="mono">{d.names.filter((x: any) => x.kind === 'name').map((x: any) => x.value).join(', ') || '–'}</dd>
            <dt>IPs</dt><dd class="mono">{[...new Set([...(hs.ips ?? []), ...d.names.filter((x: any) => x.kind === 'ip').map((x: any) => x.value)])].join(', ') || '–'}</dd>
            <dt>Connected at</dt><dd class="mono">{hs.connect_addr}{hs.connect_port && hs.connect_port !== 22 ? ':' + hs.connect_port : ''}</dd>
            <dt>OS</dt><dd>{hs.os ?? '–'}</dd>
            <dt>Kernel</dt><dd class="mono">{hs.kernel ?? '–'}</dd>
            <dt>Groups</dt><dd class="mono">{Object.entries(d.groups).map(([k, v]) => `${k}: ${v}`).join(' · ') || '–'}</dd>
            <dt>Scan time</dt><dd class="num">{hs.duration_ms !== null ? `${(hs.duration_ms / 1000).toFixed(1)} s` : '–'}</dd>
          </dl>
          <h3 class="sub-title">Host keys</h3>
          {#if d.host_keys.length}
            <ul class="hk-list">{#each d.host_keys as k}<li><KeyType alg={k.alg} bits={k.bits} /><Fp fp={k.fp} full /></li>{/each}</ul>
          {:else}<p class="secondary dense">No host key was collected.</p>{/if}
        </section>
        <section class="panel">
          <h2 class="section-title">Access counts</h2>
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
        <section class="panel user" id="user-{u.username}" class:target={target === `user-${u.username}`}>
          <h2 class="uh"><span class="mono section-title">{u.username || '(system files)'}</span>
            {#if acc}<span class="kchip">uid {acc.uid}</span><span class="kchip">{acc.shell || 'no shell'}</span>{/if}
            {#each userChips(u.username) as c}{#if c === 'missing'}<span class="badge sev-medium"><Glyph kind="medium" />missing</span>{:else}<span class="kchip">{c}</span>{/if}{/each}
          </h2>
          {#if auth.length}
            <h3 class="sub-title">Authorized keys</h3>
            <div class="table-wrap"><table class="t">
              <thead><tr><th>File:line</th><th>Strength</th><th>Type</th><th>Fingerprint</th><th>Comment</th><th>Options</th><th>Origin</th></tr></thead>
              <tbody>{#each auth as a (a.id)}<tr>
                <td class="mono" title={fileLine(a.file, a.line)}>{midTrunc(fileLine(a.file, a.line), 36)}</td>
                <td><StrengthChip strength={a.strength} /></td>
                <td><KeyType alg={a.alg} bits={a.bits} /></td>
                <td><Fp fp={a.fp} href={keyHref(sid, a.fp)} /></td>
                <td class="mono">{a.comment ?? '–'}{#if a.label}<div class="meta secondary sans">“{a.label}”</div>{/if}</td>
                <td><OptionChips options={a.options} /></td>
                <td class="nowrap">{#if a.origin === 'ca'}<span class="kchip">CA trusted</span>
                  {:else if a.origin === 'known'}<a href={keyHref(sid, a.fp)}>Known private holder ({a.holders})</a>
                  {:else}<span class="sev-info unk"><Glyph kind="unknown" /></span> Unknown origin{/if}</td>
              </tr>{/each}</tbody>
            </table></div>
          {/if}
          {#if priv.length}
            <h3 class="sub-title">Private keys</h3>
            <div class="table-wrap"><table class="t">
              <thead><tr><th>Path</th><th>Type</th><th>Fingerprint</th><th>Encrypted</th><th>Mode</th><th>Owner</th></tr></thead>
              <tbody>{#each priv as p (p.id)}<tr>
                <td class="mono" title={p.path}>{midTrunc(p.path, 40)}</td>
                <td><span class="row nowrap"><KeyType alg={p.alg} bits={p.bits} /><StrengthChip strength={p.strength} /></span></td>
                <td><Fp fp={p.fp} href={keyHref(sid, p.fp)} /></td>
                <td>{#if p.encrypted === 'no'}<span class="badge sev-medium"><Glyph kind="medium" />no</span>{:else}{p.encrypted}{/if}</td>
                <td class="mono">{#if p.mode_bad}<span class="badge sev-high"><Glyph kind="high" />{p.mode}</span>{:else}{p.mode ?? '–'}{/if}</td>
                <td class="mono">{p.owner ?? '–'}</td>
              </tr>{/each}</tbody>
            </table></div>
          {/if}
          {#if kh.length}
            <h3 class="sub-title">known_hosts</h3>
            {#if unmatchedFor(u.username) > 0}<p class="dense secondary">{plural2(unmatchedFor(u.username))} could not be matched.</p>{/if}
            <div class="table-wrap"><table class="t">
              <thead><tr><th>File:line</th><th>Pattern</th><th>Resolved host</th><th>Key</th><th>Match</th></tr></thead>
              <tbody>{#each kh as k (k.id)}<tr>
                <td class="mono" title={fileLine(k.file, k.line)}>{midTrunc(fileLine(k.file, k.line), 36)}</td>
                <td class="mono">{#if k.hashed}<span class="muted">hashed</span>{#if k.resolved_value}{' = ' + k.resolved_value}{/if}{:else}{k.patterns.join(',')}{/if}{#if k.marker} <span class="kchip">{k.marker}</span>{/if}</td>
                <td class="mono">{#if k.target_host_id}<a href={hostHref(sid, k.target_host_id)}>{k.target}</a>{:else}<span class="muted">–</span>{/if}</td>
                <td><span class="row nowrap"><KeyType alg={k.key_alg} /><Fp fp={k.key_fp} /></span></td>
                <td>{#if k.matches_actual === 'yes'}matches{:else if k.matches_actual === 'no'}<span class="badge sev-low"><Glyph kind="low" />stale</span>{:else}<span class="muted">unknown</span>{/if}</td>
              </tr>{/each}</tbody>
            </table></div>
          {/if}
          {#if cfg.length}
            <h3 class="sub-title">ssh config</h3>
            <div class="table-wrap"><table class="t">
              <thead><tr><th>File:line</th><th>Host</th><th>HostName</th><th>User</th><th>Port</th><th>IdentityFile</th><th>ProxyJump</th></tr></thead>
              <tbody>{#each cfg as c}<tr>
                <td class="mono" title={fileLine(c.file, c.line)}>{midTrunc(fileLine(c.file, c.line), 36)}</td>
                <td class="mono">{c.host_pattern ?? '–'}</td><td class="mono">{c.hostname ?? '–'}</td><td class="mono">{c.user ?? '–'}</td>
                <td class="mono num">{c.port ?? '–'}</td><td class="mono">{c.identity_files.join(', ') || '–'}</td><td class="mono">{c.proxyjump ?? '–'}</td>
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
          <thead><tr><th>Host · user</th><th>File:line</th><th>Key</th><th>Match</th></tr></thead>
          <tbody>
            {#each d.known_by as k (k.id)}
              <tr>
                <td class="mono"><a href={hostHref(sid, k.host_id)}>{k.host}</a> · {k.username || '(system)'}</td>
                <td class="mono" title={fileLine(k.file, k.line)}>{midTrunc(fileLine(k.file, k.line), 40)}{#if k.hashed} <span class="muted">(hashed)</span>{/if}</td>
                <td><span class="row nowrap"><KeyType alg={k.key_alg} /><Fp fp={k.key_fp} /></span></td>
                <td>{#if k.matches_actual === 'yes'}matches{:else if k.matches_actual === 'no'}<span class="badge sev-low"><Glyph kind="low" />Stale – key no longer presented</span>{:else}<span class="muted">unknown</span>{/if}</td>
              </tr>
            {:else}<tr><td class="empty" colspan="4">No scanned host has {name} in its known_hosts.</td></tr>{/each}
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
              <tr class="pinned"><td>{NICE[r.name] ?? r.name}</td><td class="mono wrap-any">{r.value}{#if rk} <SevBadge severity={rk} />{/if}</td><td class="secondary">{r.source}</td><td class="mono">{fileLine(r.file, r.line) || '–'}</td></tr>
            {/each}
            {#each showAllSshd ? sshd.rest : [] as r}
              <tr><td>{NICE[r.name] ?? r.name}</td><td class="mono wrap-any">{r.value}</td><td class="secondary">{r.source}</td><td class="mono">{fileLine(r.file, r.line) || '–'}</td></tr>
            {/each}
            {#if !sshd.pin.length && !sshd.rest.length}<tr><td class="empty" colspan="4">No sshd settings were read on {name}.</td></tr>{/if}
          </tbody>
        </table></div>
        {#if sshd.rest.length}<div class="more"><button class="btn ghost" onclick={() => (showAllSshd = !showAllSshd)}>{showAllSshd ? 'Show the relevant settings only' : `Show all ${n(sshd.rest.length + sshd.pin.length + sshd.sec.length)} settings`}</button></div>{/if}
      </section>
      {#each sshd.match as m}
        <section class="panel"><h3 class="sub-title">Match block (shown as written; not evaluated)</h3><pre class="raw">{m.value}</pre>
          {#if m.file}<p class="meta mono secondary">{fileLine(m.file, m.line)}</p>{/if}</section>
      {/each}

    {:else if tab === 'accounts'}
      <div class="row"><label class="check"><input type="checkbox" bind:checked={showAllAccounts} />Show all accounts</label>
        {#if !showAllAccounts}<span class="meta secondary">Only accounts with SSH data</span>{/if}</div>
      <section class="panel flush">
        <div class="table-wrap"><table class="t">
          <thead><tr><th>Username</th><th class="r">UID</th><th>Shell</th><th>Login shell</th><th>Password</th><th>Expiry</th></tr></thead>
          <tbody>
            {#each d.accounts.filter((a: any) => showAllAccounts || sshUsers.has(a.username)) as a (a.username)}
              <tr><td class="mono">{#if sshUsers.has(a.username)}<a href="?tab=users#user-{encodeURIComponent(a.username)}">{a.username}</a>{:else}{a.username}{/if}</td><td class="r num">{a.uid}</td><td class="mono">{a.shell || '–'}</td>
                <td>{a.login_shell ? 'yes' : 'no'}</td><td>{a.pw_state}</td><td class="mono">{a.expiry ?? '–'}</td></tr>
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

<script lang="ts" module>
  function plural2(v: number) { return v === 1 ? '1 hashed entry' : `${v} hashed entries`; }
</script>

<style>
  .head { display: flex; flex-direction: column; gap: var(--s4); position: sticky; top: 48px; z-index: 5; background: var(--bg-page);
    padding-top: var(--s2); }
  :global(.has-synth) .head { top: 80px; }
  .line { display: flex; flex-wrap: wrap; align-items: center; gap: var(--s2); }
  .sans { font-family: var(--sans); }
  .reasons { margin: var(--s2) 0; padding-left: var(--s5); font-size: 13px; }
  .att { margin-top: var(--s3); max-width: 720px; }
  .hk { margin: var(--s3) 0; }
  .tabpanel { display: flex; flex-direction: column; gap: var(--s5); }
  .ov { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr); gap: var(--s5); align-items: start; }
  .ov .section-title { margin-bottom: var(--s4); }
  .sub-title { font-size: 14px; line-height: 20px; font-weight: 600; margin: var(--s5) 0 var(--s3); }
  .hk-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: var(--s3); }
  .hk-list li { display: flex; gap: var(--s3); align-items: center; flex-wrap: wrap; }
  .cnote { margin-top: var(--s4); }
  .user { scroll-margin-top: 220px; }
  .user.target { border-color: var(--accent); }
  .uh { display: flex; gap: var(--s3); align-items: center; flex-wrap: wrap; }
  .unk { color: var(--c); }
  .emptytab { text-align: center; padding: var(--s7); color: var(--text-secondary); }
  .more { padding: var(--s3) var(--s4); }
  .exp { position: relative; }
  .expmenu { right: 0; top: 36px; display: flex; flex-direction: column; padding: var(--s2) 0; min-width: 180px; }
  .expmenu a { padding: var(--s3) var(--s4); color: var(--text-primary); }
  .expmenu a:hover { background: var(--bg-hover); text-decoration: none; }
  :global(tr[id^='finding-']) { scroll-margin-top: 240px; }
  @media (max-width: 1100px) { .ov { grid-template-columns: minmax(0, 1fr); } .head { position: static; } }
</style>
