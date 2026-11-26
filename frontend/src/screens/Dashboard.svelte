<script lang="ts">
  // Dashboard (design-revision §5.1): one Scan summary panel, findings first; top findings; inbound/outbound.
  import { api } from '../lib/api';
  import { live, Resource, runningScan } from '../lib/state.svelte';
  import { fileLine, fmtDuration, fmtTime, midTrunc, n, ruleTitle, SEV_LABEL, SEVERITIES, STRENGTH_LABEL, utcTitle } from '../lib/format';
  import { hostHref, keyHref } from '../lib/links';
  import PageHead from '../components/PageHead.svelte';
  import Notices from '../components/Notices.svelte';
  import Strip from '../components/Strip.svelte';
  import Meter from '../components/Meter.svelte';
  import Field from '../components/Field.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';
  import Skeleton from '../components/Skeleton.svelte';

  let { scan }: { scan: any } = $props();
  const sid = scan.id;
  const res = new Resource<any>();
  function load() {
    res.load(async () => {
      const [detail, keys, findings, inb, outb] = await Promise.all([
        api(`/scans/${sid}`), api(`/scans/${sid}/keys?page_size=1`), api(`/scans/${sid}/findings?page_size=10`),
        api(`/scans/${sid}/ranking?direction=in&metric=hosts&limit=5`), api(`/scans/${sid}/ranking?direction=out&metric=hosts&limit=5`),
      ]);
      return { detail, keys, findings, inb: inb.items, outb: outb.items };
    });
  }
  load();

  const running = $derived(runningScan());
  const prog = $derived(live.scan && running && live.scan.id === running.id ? live.scan.progress : null);
  const progPct = $derived(prog ? (prog.done / Math.max(1, prog.done + prog.queued + prog.running)) * 100 : 0);

  // rows of the summary columns: level = bars of the count-form badge, -1 = plain text (OK, Good, not scanned)
  const hostClasses = $derived.by(() => {
    const h: Record<string, number> = res.data?.detail.counts?.hosts ?? {};
    const sum = (ks: string[]) => ks.reduce((a, k) => a + (h[k] ?? 0), 0);
    const known = ['ok', 'partial', 'output_limit', 'unreachable', 'timeout', 'auth_failed', 'hostkey_mismatch', 'hostkey_unknown'];
    const other = Object.entries(h).filter(([k]) => !known.includes(k)).reduce((a, [, v]) => a + (v as number), 0);
    const hk = sum(['hostkey_mismatch', 'hostkey_unknown']);
    return [
      { key: 'ok', label: 'OK', sev: 'low', level: -1, v: h.ok ?? 0, filter: 'ok' },
      { key: 'partial', label: 'Partial', sev: 'medium', level: 2, v: sum(['partial', 'output_limit']), filter: 'partial,output_limit' },
      { key: 'unreachable', label: 'Unreachable', sev: 'high', level: 3, v: sum(['unreachable', 'timeout', 'auth_failed']), filter: 'unreachable,timeout,auth_failed' },
      ...(hk ? [{ key: 'hostkey', label: 'Host key changed', sev: 'critical', level: 4, v: hk, filter: 'hostkey_mismatch,hostkey_unknown' }] : []),
      { key: 'other', label: 'Not scanned', sev: 'info', level: -1, v: other, filter: Object.keys(h).filter((k) => !known.includes(k)).join(','), muted: true },
    ];
  });
  const sevClasses = $derived(SEVERITIES.map((s) => ({ key: s, label: SEV_LABEL[s], sev: s, level: { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s]!, v: res.data?.detail.counts?.findings?.[s] ?? 0 })));
  const strClasses = $derived(['critical', 'weak', 'ok', 'good', 'unknown']
    .map((s) => ({ key: s, label: STRENGTH_LABEL[s], v: res.data?.keys.strength_counts?.[s] ?? 0,
      sev: { critical: 'critical', weak: 'medium', ok: 'low', good: 'good', unknown: 'info' }[s]!,
      level: { critical: 4, weak: 2 }[s as 'critical'] ?? -1, good: s === 'good', muted: s === 'unknown' }))
    .filter((c) => c.v > 0 || c.key !== 'unknown'));
  const sevMax = $derived(Math.max(1, ...sevClasses.map((c) => c.v)));
  const hostsTotal = $derived(res.data?.detail.counts?.hosts_total ?? 0);
  const connected = $derived(res.data?.detail.counts?.hosts_connected ?? 0);
  const inMax = $derived(Math.max(1, ...(res.data?.inb ?? []).map((r: any) => r.value)));
  const outMax = $derived(Math.max(1, ...(res.data?.outb ?? []).map((r: any) => r.value)));

  function findingHref(f: any) {
    if (f.host_id !== null && f.host_id !== undefined) return hostHref(sid, f.host_id, 'findings', `finding-${f.id}`);
    return keyHref(sid, f.fp) + '?tab=findings';
  }
  let exportOpen = $state(false);
</script>

<svelte:window onclick={(e) => { if (!(e.target as HTMLElement).closest('.exp')) exportOpen = false; }} />

<PageHead title="Dashboard">
  {#snippet fields()}
    <Field label="Scan">Scan #{scan.id} <span class="secondary">{scan.label || 'unlabelled'}</span></Field>
    <Field label="Entry point" value={scan.entry_host ?? '–'} />
    <Field label={scan.status === 'completed' ? 'Started' : scan.status === 'running' ? 'Running since' : scan.status === 'failed' ? 'Failed' : 'Aborted'} value={fmtTime(scan.started_at)} title={utcTitle(scan.started_at)} />
    <Field label="Duration" value={scan.finished_at ? fmtDuration(scan.started_at, scan.finished_at) : '–'} />
    <Field label="Hosts">{n(connected)} scanned{#if hostsTotal > connected}<span class="secondary">, {n(hostsTotal - connected)} more seen, not scanned</span>{/if}</Field>
  {/snippet}
  {#snippet actions()}
    <div class="exp">
      <button class="btn" aria-haspopup="menu" aria-expanded={exportOpen} onclick={() => (exportOpen = !exportOpen)}>Export findings<svg class="chev" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M3 4.5 6 7.5 9 4.5" fill="none" stroke="currentColor" stroke-width="1.5" /></svg></button>
      {#if exportOpen}
        <div class="popover expmenu" role="menu">
          <a role="menuitem" href="/api/scans/{sid}/export/findings.csv" download>Findings (CSV)</a>
          <a role="menuitem" href="/api/scans/{sid}/export/findings.json" download>Findings (JSON)</a>
        </div>
      {/if}
    </div>
    <a class="btn primary" href="/s/{sid}/heatmap">Open heatmap</a>
  {/snippet}
</PageHead>

{#if running && prog}
  <div class="strip info prog" aria-live="polite">
    <div class="pb">
      <p><span class="s600">Scan #{running.id} running</span></p>
      <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow={Math.round(progPct)}><span style:width="{progPct}%"></span></div>
      <dl class="ctx">
        <Field label="Depth" value={prog.depth ?? 0} /><Field label="Queued" value={n(prog.queued)} /><Field label="Running" value={n(prog.running)} />
        <Field label="Done" value={n(prog.done)} /><Field label="Partial" value={n(prog.partial ?? 0)} /><Field label="Unreachable" value={n(prog.unreachable ?? 0)} />
      </dl>
    </div>
  </div>
{/if}

<Notices {scan} partial />
{#if connected === 1 && scan.status === 'completed'}
  <Strip role="info">Only the entry point was found; it has no known_hosts/ssh config references. Add seeds to scan more.</Strip>
{/if}

{#if res.error}
  <ErrorPanel thing="the dashboard" message={res.error} retry={load} />
{:else if !res.data}
  {#if res.slow}<div class="panel flush"><Skeleton rows={12} /></div>{/if}
{:else}
  <section class="panel flush summary">
    <header><h2 class="section-title">Scan summary</h2></header>
    <div class="cols">
      {#snippet col(title: string, classes: any[], href: (c: any) => string, bars: boolean, max: number)}
        <div class="col">
          <h3 class="ct">{title}</h3>
          <ul>
            {#each classes as c}
              <li><a class="srow" class:bars href={href(c)} data-stat="{title}:{c.key}">
                <span class="lv sev-{c.sev}">{#if c.level >= 0}<Meter level={c.level} />{/if}</span>
                <span class="sl" class:muted={c.muted}>{c.label}{#if c.good}<svg class="ck" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M2.5 6.5 5 9l4.5-6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg>{/if}</span>
                <span class="figure">{n(c.v)}</span>
                {#if bars}<span class="hb"><span style:width="{(c.v / max) * 100}%" class:zero={c.v === 0}></span></span>{/if}
              </a></li>
            {/each}
          </ul>
        </div>
      {/snippet}
      {@render col('Findings by severity', sevClasses, (c) => `/s/${sid}/findings?sev=${c.key}`, true, sevMax)}
      {@render col('Hosts by status', hostClasses, (c) => `/s/${sid}/hosts?status=${c.filter}`, false, 1)}
      {@render col('Keys by strength', strClasses, (c) => `/s/${sid}/keys?strength=${c.key}`, false, 1)}
    </div>
  </section>

  <div class="lower">
    <section class="panel flush">
      <header><h2 class="section-title">Top findings</h2><a class="btn" href="/s/{sid}/findings">All findings</a></header>
      {#if res.data.findings.items.length === 0}
        <p class="emptyrow">No findings in scan #{sid}.</p>
      {:else}
        <div class="tfh" aria-hidden="true"><span>Severity</span><span>Finding</span><span>Location</span><span>Recommendation</span></div>
        <ol class="tf">
          {#each res.data.findings.items as f (f.id)}
            <li>
              <span class="c1"><SevBadge severity={f.severity} /></span>
              <span class="c2"><a class="title plain" href={findingHref(f)}>{ruleTitle(f.rule, f)}</a></span>
              <span class="c3">
                <span class="loc">{#if f.host}<a href={hostHref(sid, f.host_id)}>{f.host}</a>{:else}<span class="muted">all hosts</span>{/if}{#if f.username}<span class="usr">{f.username}</span>{/if}</span>
                {#if f.file}<span class="mono path" title={fileLine(f.file, f.line)}>{midTrunc(fileLine(f.file, f.line), 40)}</span>{/if}
              </span>
              <span class="c4 secondary" title={f.recommendation}>{f.recommendation}</span>
            </li>
          {/each}
        </ol>
      {/if}
    </section>
    <section class="panel flush io">
      {#snippet ranking(title: string, help: string, rows: any[], max: number, empty: string)}
        <div class="rk">
          <header><h2 class="section-title">{title}</h2><p class="help">{help}</p></header>
          {#if rows.length === 0}<p class="secondary dense pad">{empty}</p>{:else}
          <ol class="rank">
            {#each rows as r}
              <li><a class="trunc" href={hostHref(sid, r.host_id)} title={r.display_name}>{r.display_name}</a><span class="num">{r.value}</span><span class="rb"><span style:width="{(r.value / max) * 100}%"></span></span></li>
            {/each}
          </ol>{/if}
        </div>
      {/snippet}
      {@render ranking('Most inbound', 'Hosts that can be reached from most hosts', res.data.inb, inMax, 'No host can be reached from another scanned host.')}
      {@render ranking('Most outbound', 'Hosts that can reach most hosts', res.data.outb, outMax, 'No host can reach another scanned host.')}
    </section>
  </div>
{/if}

<style>
  .chev { color: var(--text-muted); }
  .prog { align-items: flex-start; }
  .pb { flex: 1; display: flex; flex-direction: column; gap: var(--s3); }
  .s600 { font-weight: 600; }
  .bar { height: 4px; background: var(--bg-subtle); border-radius: 2px; overflow: hidden; }
  .bar span { display: block; height: 100%; background: var(--accent); transition: width var(--t-mid) ease-out; }
  /* Scan summary: three columns divided by border.subtle lines; rows 32 px */
  .cols { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .col { padding: var(--s4) var(--s5) var(--s5); min-width: 0; }
  .col + .col { border-left: 1px solid var(--border-subtle); }
  .col:first-child { grid-column: auto; }
  .ct { font-size: 12px; line-height: 16px; font-weight: 500; color: var(--text-secondary); margin-bottom: var(--s2); }
  .col ul { list-style: none; margin: 0; padding: 0; }
  .srow { display: grid; grid-template-columns: 16px minmax(0, 1fr) 48px; gap: var(--s3); align-items: center; height: 32px;
    color: var(--text-primary); text-decoration: none; border-radius: var(--r1); padding: 0 var(--s2); margin: 0 calc(-1 * var(--s2)); }
  .srow.bars { grid-template-columns: 16px minmax(72px, 1fr) 48px minmax(0, 1.3fr); }
  .srow:hover { background: var(--bg-hover); color: var(--text-primary); text-decoration: none; }
  .srow:hover .sl { text-decoration: underline; }
  .lv { color: var(--c); display: inline-flex; }
  .sl { font-size: 13px; line-height: 20px; display: inline-flex; align-items: center; gap: var(--s2); color: var(--text-primary); }
  .sl.muted { color: var(--text-muted); }
  .ck { color: var(--text-secondary); }
  .figure { text-align: right; }
  .hb { height: 6px; padding-left: var(--s3); display: block; }
  .hb span { display: block; height: 6px; background: var(--border-default); border-radius: 1px; }
  .hb span.zero { width: 1px !important; }
  .lower { display: grid; grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr); gap: var(--s5); align-items: start; }
  .tfh, .tf li { display: grid; grid-template-columns: 104px minmax(0, 1.5fr) minmax(0, 1.1fr) minmax(0, 1fr); gap: var(--s4);
    padding: 0 var(--s5); }
  .tfh { height: 36px; align-items: center; background: var(--bg-subtle); border-bottom: 1px solid var(--border-default);
    font-size: 12px; line-height: 16px; font-weight: 500; color: var(--text-secondary); }
  .tf { list-style: none; margin: 0; padding: 0; }
  .tf li { align-items: start; padding-top: 10px; padding-bottom: 10px; min-height: 56px; border-bottom: 1px solid var(--border-subtle);
    font-size: 13px; line-height: 20px; }
  .tf li:last-child { border-bottom: 0; }
  .tf li:hover { background: var(--bg-hover); }
  .c2, .c3 { display: flex; flex-direction: column; min-width: 0; }
  .title { font-weight: 500; }
  .loc { display: flex; gap: var(--s3); white-space: nowrap; overflow: hidden; }
  .loc a { font-weight: 500; }
  .usr { color: var(--text-secondary); }
  .path { font-size: 12px; line-height: 16px; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .c4 { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .emptyrow { padding: var(--s6) var(--s5); color: var(--text-secondary); }
  .io .rk + .rk { border-top: 1px solid var(--border-subtle); }
  .io header { display: flex; flex-direction: column; align-items: flex-start; gap: 0; padding: var(--s4) var(--s5) var(--s2); }
  .pad { padding: 0 var(--s5) var(--s4); }
  .rank { list-style: none; margin: 0; padding: 0 var(--s5) var(--s4); }
  .rank li { display: grid; grid-template-columns: minmax(0, 1fr) 32px 40%; gap: var(--s3); align-items: center; height: 32px; font-size: 13px; }
  .rank a { font-weight: 500; }
  .rank .num { text-align: right; }
  .rb span { display: block; height: 6px; background: var(--border-default); border-radius: 1px; }
  @media (max-width: 1100px) { .lower { grid-template-columns: minmax(0, 1fr); } }
  @media (max-width: 900px) {
    .cols { grid-template-columns: minmax(0, 1fr); }
    .col + .col { border-left: 0; border-top: 1px solid var(--border-subtle); }
  }
  @media (max-width: 700px) {
    .tfh { display: none; }
    .tf li { grid-template-columns: minmax(0, 1fr); gap: var(--s1); padding: var(--s3) var(--s4); }
    .c4 { white-space: normal; display: -webkit-box; -webkit-line-clamp: 2; line-clamp: 2; -webkit-box-orient: vertical; }
  }
</style>
