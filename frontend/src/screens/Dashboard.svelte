<script lang="ts">
  // Dashboard (design §4.2).
  import { api } from '../lib/api';
  import { live, Resource, runningScan } from '../lib/state.svelte';
  import { fileLine, fmtClock, fmtTime, midTrunc, n, plural, ruleTitle, SEV_LABEL, SEVERITIES, STRENGTH_LABEL, utcTitle } from '../lib/format';
  import { hostHref, keyHref } from '../lib/links';
  import PageHead from '../components/PageHead.svelte';
  import Notices from '../components/Notices.svelte';
  import Strip from '../components/Strip.svelte';
  import Glyph from '../components/Glyph.svelte';
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

  const hostClasses = $derived.by(() => {
    const h: Record<string, number> = res.data?.detail.counts?.hosts ?? {};
    const sum = (ks: string[]) => ks.reduce((a, k) => a + (h[k] ?? 0), 0);
    const known = ['ok', 'partial', 'output_limit', 'unreachable', 'timeout', 'auth_failed', 'hostkey_mismatch', 'hostkey_unknown'];
    const other = Object.entries(h).filter(([k]) => !known.includes(k)).reduce((a, [, v]) => a + (v as number), 0);
    return [
      { key: 'ok', label: 'ok', sev: 'low', glyph: 'dot', v: h.ok ?? 0, filter: 'ok' },
      { key: 'partial', label: 'partial', sev: 'medium', glyph: 'medium', v: sum(['partial', 'output_limit']), filter: 'partial,output_limit' },
      { key: 'unreachable', label: 'unreachable', sev: 'high', glyph: 'high', v: sum(['unreachable', 'timeout', 'auth_failed']), filter: 'unreachable,timeout,auth_failed' },
      { key: 'hostkey', label: 'host key', sev: 'critical', glyph: 'critical', v: sum(['hostkey_mismatch', 'hostkey_unknown']), filter: 'hostkey_mismatch,hostkey_unknown' },
      { key: 'other', label: 'not scanned', sev: 'info', glyph: 'info', v: other, filter: Object.keys(h).filter((k) => !known.includes(k)).join(',') },
    ];
  });
  const sevClasses = $derived(SEVERITIES.map((s) => ({ key: s, label: SEV_LABEL[s], sev: s, glyph: s, v: res.data?.detail.counts?.findings?.[s] ?? 0 })));
  const strClasses = $derived(['critical', 'weak', 'ok', 'good', 'unknown'].map((s) => ({
    key: s, label: STRENGTH_LABEL[s], v: res.data?.keys.strength_counts?.[s] ?? 0,
    sev: { critical: 'critical', weak: 'medium', ok: 'low', good: 'good', unknown: 'info' }[s]!,
    glyph: { critical: 'critical', weak: 'medium', ok: 'dot', good: 'good', unknown: 'unknown' }[s]!,
  })));
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

{#if running && prog}
  <section class="panel prog" aria-live="polite">
    <h2 class="section-title">Scan #{running.id} running</h2>
    <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow={Math.round(progPct)}><span style:width="{progPct}%"></span></div>
    <p class="num secondary">Depth {prog.depth ?? 0} · {n(prog.queued)} queued · {n(prog.running)} running · {n(prog.done)} done · {n(prog.partial ?? 0)} partial · {n(prog.unreachable ?? 0)} unreachable</p>
  </section>
{/if}

<PageHead title="Scan #{scan.id} · {scan.label || 'unlabelled'}">
  {#snippet sub()}
    <span title={utcTitle(scan.started_at)}>{scan.status === 'completed' ? 'Completed' : scan.status === 'running' ? 'Running since' : scan.status === 'failed' ? 'Failed' : 'Aborted'} {fmtTime(scan.started_at)}{#if scan.finished_at}–{fmtClock(scan.finished_at)}{/if}</span>
    · {plural(connected, 'host')} scanned{#if hostsTotal > connected}{` (${n(hostsTotal - connected)} more seen, not scanned)`}{/if} · entry <span class="mono">{scan.entry_host ?? '–'}</span> · <a href="/s/{sid}/crawl">crawl tree →</a>
  {/snippet}
  {#snippet actions()}
    <a class="btn primary" href="/s/{sid}/heatmap">Open heatmap</a>
    <div class="exp">
      <button class="btn" aria-haspopup="menu" aria-expanded={exportOpen} onclick={() => (exportOpen = !exportOpen)}>Export findings ▾</button>
      {#if exportOpen}
        <div class="popover expmenu" role="menu">
          <a role="menuitem" href="/api/scans/{sid}/export/findings.csv" download>Findings (CSV)</a>
          <a role="menuitem" href="/api/scans/{sid}/export/findings.json" download>Findings (JSON)</a>
        </div>
      {/if}
    </div>
  {/snippet}
</PageHead>

<Notices {scan} partial />
{#if connected === 1 && scan.status === 'completed'}
  <Strip role="info">Only the entry point was found; it has no known_hosts/ssh config references. Add seeds to scan more.</Strip>
{/if}

{#if res.error}
  <ErrorPanel thing="the dashboard" message={res.error} retry={load} />
{:else if !res.data}
  {#if res.slow}<div class="panel flush"><Skeleton rows={12} /></div>{/if}
{:else}
  <div class="stats">
    {#snippet stat(title: string, classes: any[], href: (c: any) => string, total: number)}
      <section class="panel">
        <h2 class="section-title">{title}</h2>
        <div class="figs">
          {#each classes as c}
            {#if c.v > 0 || ['ok', 'critical', 'high'].includes(c.key)}
              <a class="fig sev-{c.sev}" href={href(c)} data-stat="{title}:{c.key}"><span class="figure">{n(c.v)}</span><span class="fl"><span class="g"><Glyph kind={c.glyph} /></span>{c.label}</span></a>
            {/if}
          {/each}
        </div>
        <div class="stack-bar" aria-hidden="true">
          {#each classes as c}{#if c.v > 0}<span class="sb sev-{c.sev}" style:flex-grow={c.v}></span>{/if}{/each}
          {#if total === 0}<span class="sb empty" style:flex-grow="1"></span>{/if}
        </div>
      </section>
    {/snippet}
    {@render stat('Hosts by status', hostClasses, (c) => `/s/${sid}/hosts?status=${c.filter}`, hostsTotal)}
    {@render stat('Findings by severity', sevClasses, (c) => `/s/${sid}/findings?sev=${c.key}`, res.data.detail.counts?.findings_total ?? 0)}
    {@render stat('Keys by strength', strClasses, (c) => `/s/${sid}/keys?strength=${c.key}`, res.data.keys.total_all)}
  </div>

  <div class="lower">
    <section class="panel flush">
      <header><h2 class="section-title">Top findings</h2><a href="/s/{sid}/findings">All findings →</a></header>
      {#if res.data.findings.items.length === 0}
        <p class="emptyrow">No findings in scan #{sid}.</p>
      {:else}
        <ul class="tf">
          {#each res.data.findings.items as f (f.id)}
            <li>
              <a class="tfrow" href={findingHref(f)}>
                <span class="c1"><SevBadge severity={f.severity} /></span>
                <span class="c2">
                  <span class="title">{ruleTitle(f.rule, f)}</span>
                  <span class="mono loc">{f.host ?? 'all hosts'}{#if f.username}{' · ' + f.username}{/if}{#if f.file}<span class="muted">{'  ' + midTrunc(fileLine(f.file, f.line), 40)}</span>{/if}</span>
                </span>
                <span class="c3 secondary trunc" title={f.recommendation}>{f.recommendation}</span>
              </a>
            </li>
          {/each}
        </ul>
      {/if}
    </section>
    <div class="io">
      {#snippet ranking(title: string, rows: any[], max: number, empty: string)}
        <section class="panel">
          <h2 class="section-title">{title}</h2>
          {#if rows.length === 0}<p class="secondary dense">{empty}</p>{:else}
          <ol class="rank">
            {#each rows as r}
              <li><a class="mono trunc" href={hostHref(sid, r.host_id)} title={r.display_name}>{r.display_name}</a><span class="num">{r.value}</span><span class="rb"><span style:width="{(r.value / max) * 100}%"></span></span></li>
            {/each}
          </ol>{/if}
        </section>
      {/snippet}
      {@render ranking('Most inbound (hosts that can be reached from most hosts)', res.data.inb, inMax, 'No host can be reached from another scanned host.')}
      {@render ranking('Most outbound (hosts that can reach most hosts)', res.data.outb, outMax, 'No host can reach another scanned host.')}
    </div>
  </div>
{/if}

<style>
  .prog { display: flex; flex-direction: column; gap: var(--s3); }
  .bar { height: 8px; background: var(--bg-sunken); border-radius: var(--r1); overflow: hidden; }
  .bar span { display: block; height: 100%; background: var(--accent); transition: width var(--t-mid) ease-out; }
  .stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: var(--s5); }
  .stats .panel { display: flex; flex-direction: column; gap: var(--s4); }
  .figs { display: flex; flex-wrap: wrap; gap: var(--s3) var(--s5); }
  .fig { display: flex; flex-direction: column; color: var(--text-primary); text-decoration: none; }
  .fig:hover { text-decoration: none; color: var(--text-primary); }
  .fig:hover .fl { text-decoration: underline; }
  .fl { display: inline-flex; gap: var(--s2); align-items: center; font-size: 13px; color: var(--text-secondary); }
  .g { color: var(--c); display: inline-flex; }
  .stack-bar { display: flex; gap: 2px; height: 6px; margin-top: auto; }
  .stack-bar .sb { background: var(--c); border-radius: 1px; min-width: 2px; }
  .stack-bar .sb.empty { background: var(--bg-sunken); }
  .lower { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); gap: var(--s5); align-items: start; }
  .lower > .panel > header { padding-bottom: var(--s3); margin-bottom: 0; border-bottom: 1px solid var(--border-subtle); }
  .tf { list-style: none; margin: 0; padding: 0; }
  .tfrow { display: grid; grid-template-columns: 96px minmax(0, 1.3fr) minmax(0, 1fr); gap: var(--s4); align-items: center;
    padding: var(--s2) var(--s5); min-height: 52px; color: var(--text-primary); border-bottom: 1px solid var(--border-subtle); text-decoration: none; }
  .tfrow:hover { background: var(--bg-hover); text-decoration: none; color: var(--text-primary); }
  .c2 { display: flex; flex-direction: column; min-width: 0; }
  .title { font-size: 14px; }
  .loc { font-size: 13px; line-height: 18px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .c3 { font-size: 13px; display: block; }
  .emptyrow { padding: var(--s6) var(--s5); text-align: center; color: var(--text-secondary); }
  .io { display: flex; flex-direction: column; gap: var(--s5); }
  .io .section-title { font-size: 14px; line-height: 20px; margin-bottom: var(--s3); }
  .rank { list-style: none; margin: 0; padding: 0; }
  .rank li { display: grid; grid-template-columns: minmax(0, 1fr) 40px 40%; gap: var(--s3); align-items: center; height: 28px; font-size: 13px; }
  .rank .num { text-align: right; }
  .rb span { display: block; height: 8px; background: var(--text-secondary); opacity: .4; }
  .exp { position: relative; }
  .expmenu { right: 0; top: 36px; display: flex; flex-direction: column; padding: var(--s2) 0; min-width: 180px; }
  .expmenu a { padding: var(--s3) var(--s4); color: var(--text-primary); }
  .expmenu a:hover { background: var(--bg-hover); text-decoration: none; }
  @media (max-width: 1100px) { .stats, .lower { grid-template-columns: minmax(0, 1fr); } }
</style>
