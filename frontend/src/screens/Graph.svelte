<script lang="ts">
  // Graph (design §5.6): neighbourhood of a host or key, d3-force radial layout, frozen after settling.
  import { onDestroy, tick } from 'svelte';
  import { forceCollide, forceLink, forceManyBody, forceRadial, forceSimulation, type Simulation } from 'd3-force';
  import { zoom, zoomIdentity, type ZoomBehavior } from 'd3-zoom';
  import { select } from 'd3-selection';
  import { drag } from 'd3-drag';
  import { api, fpFromUrl, fpUrl, qs } from '../lib/api';
  import { navigate, route, setQuery } from '../lib/router.svelte';
  import { Resource } from '../lib/state.svelte';
  import { EDGE_STATUS, FLAG_LABEL, fileLine, n, NOT_SCANNED, SOURCE_LABEL, STATUS_LABEL } from '../lib/format';
  import { hostHref, keyHref } from '../lib/links';
  import { commonSuffix } from '../lib/heat';
  import PageHead from '../components/PageHead.svelte';
  import Notices from '../components/Notices.svelte';
  import Strip from '../components/Strip.svelte';
  import Fp from '../components/Fp.svelte';
  import StrengthChip from '../components/StrengthChip.svelte';
  import Field from '../components/Field.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';

  let { scan }: { scan: any } = $props();
  const sid = scan.id;
  const G = $derived({
    host: route.query.get('host') ?? '', key: route.query.get('key') ?? '',
    hops: +(route.query.get('hops') ?? 1), layer: route.query.get('layer') ?? 'access',
  });
  const hasCentre = $derived(!!(G.host || G.key));
  const res = new Resource<any>();
  const load = () => res.load(() => api(`/scans/${sid}/graph` + qs({ center_host: G.host || undefined, center_key: G.key || undefined, hops: G.hops, layer: G.layer, max_nodes: 150 })));
  $effect(() => { G.host; G.key; G.hops; G.layer; if (hasCentre) load(); });

  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  type N = { id: string; kind: string; label: string; host_id?: number; status?: string; dist: number; degree: number; sev?: string | null; fp?: string;
    x?: number; y?: number; fx?: number | null; fy?: number | null; r: number };
  type L = { id: string; source: any; target: any; kind: string; cls: string; strength: string | null; count: number; links: any[]; status: string; effective: boolean };
  let nodes = $state.raw<N[]>([]);
  let links = $state.raw<L[]>([]);
  let frame = $state(0);  // bumps on every simulation tick
  let ring1 = 160, ring2 = 320;
  let suffix = $state('');
  let sim: Simulation<any, any> | null = null;
  const WIDTH = 960, HEIGHT = 680;
  const SRANK: Record<string, number> = { critical: 0, weak: 1, unknown: 2, ok: 3, good: 4 };

  function linkClass(l: any): string {
    if (l.kind === 'evidence') return 'evidence';
    if (l.status === 'restricted_blocked' || !l.effective) return 'blocked';
    if (l.status === 'unknown_origin') return 'unknown';
    if (l.status === 'restricted_ok') return 'restricted';
    return 'confirmed';
  }

  $effect(() => {
    const d = res.data;
    if (!d) return;
    sim?.stop();
    const ns: N[] = d.nodes.map((x: any) => ({ ...x, r: x.kind === 'unknown' ? 9 : Math.min(16, 6 + 2 * Math.sqrt(x.degree)) }));
    const byId = new Map(ns.map((x) => [x.id, x]));
    const merged = new Map<string, L>();
    for (const l of d.links) {
      const cls = linkClass(l);
      const k = `${l.source}|${l.target}|${l.kind}|${cls}`;
      const m = merged.get(k);
      if (m) {
        m.count += l.edge_ids.length;
        m.links.push(l);
        if ((SRANK[l.strength ?? 'unknown'] ?? 9) < (SRANK[m.strength ?? 'unknown'] ?? 9)) m.strength = l.strength;
      } else merged.set(k, { id: k, source: byId.get(l.source), target: byId.get(l.target), kind: l.kind, cls, strength: l.strength, count: l.edge_ids.length, links: [l], status: l.status, effective: l.effective });
    }
    const ls = [...merged.values()].filter((l) => l.source && l.target);
    // ring radii grow with the number of nodes on them, so a hub's neighbours do not pile up
    const cnt = [0, 0, 0];
    ns.forEach((x) => { cnt[Math.min(2, x.dist)]++; });
    ring1 = Math.max(160, (cnt[1] * 26) / (2 * Math.PI));
    ring2 = Math.max(320, ring1 + 160, (cnt[2] * 22) / (2 * Math.PI));
    suffix = commonSuffix(ns.filter((x) => x.kind === 'host').map((x) => x.label));
    const centre = ns.find((x) => x.dist === 0);
    if (centre) { centre.fx = 0; centre.fy = 0; }
    // deterministic start: spread each ring evenly
    const rings = new Map<number, N[]>();
    ns.forEach((x) => { if (!rings.has(x.dist)) rings.set(x.dist, []); rings.get(x.dist)!.push(x); });
    rings.forEach((arr, dist) => arr.forEach((x, i) => {
      if (x.fx !== undefined && x.fx !== null) return;
      const a = (i / arr.length) * Math.PI * 2;
      const rr = dist === 0 ? 0 : dist === 1 ? ring1 : ring2;
      x.x = Math.cos(a) * rr; x.y = Math.sin(a) * rr;
    }));
    sim = forceSimulation(ns as any)
      .force('link', forceLink(ls as any).distance(80).strength(0.04))
      .force('charge', forceManyBody().strength(-220))
      .force('collide', forceCollide((x: any) => x.r + 6))
      .force('radial', forceRadial((x: any) => (x.dist === 0 ? 0 : x.dist === 1 ? ring1 : ring2), 0, 0).strength(1))
      .stop();
    nodes = ns;
    links = ls;
    if (reduced) {
      for (let i = 0; i < 300; i++) sim.tick();
      frame++;
      tick().then(fit);
    } else {
      const started = performance.now();
      sim.on('tick', () => { frame++; if (performance.now() - started > 1500) { sim?.stop(); fit(); } });
      sim.on('end', fit);
      sim.alpha(1).restart();
    }
    selected = null;
    tick().then(fit);
  });
  onDestroy(() => sim?.stop());

  // ---- zoom / drag
  let svg: SVGSVGElement | undefined = $state();
  let viewport: SVGGElement | undefined = $state();
  let zb: ZoomBehavior<SVGSVGElement, unknown> | null = null;
  let transform = $state('');
  $effect(() => {
    if (!svg) return;
    zb = zoom<SVGSVGElement, unknown>().scaleExtent([0.4, 3]).on('zoom', (e) => { transform = e.transform.toString(); });
    select(svg).call(zb).on('dblclick.zoom', null);
  });
  function fit() {
    if (!svg || !zb || !nodes.length) return;
    const xs = nodes.map((x) => x.x ?? 0), ys = nodes.map((x) => x.y ?? 0);
    const minX = Math.min(...xs) - 60, maxX = Math.max(...xs) + 160, minY = Math.min(...ys) - 40, maxY = Math.max(...ys) + 40;
    const box = svg.getBoundingClientRect();
    const k = Math.max(0.4, Math.min(1.6, Math.min(box.width / (maxX - minX), box.height / (maxY - minY))));
    const t = zoomIdentity.translate(box.width / 2 - k * (minX + maxX) / 2, box.height / 2 - k * (minY + maxY) / 2).scale(k);
    select(svg).call(zb.transform, t);
  }
  function dragAction(el: SVGGElement, nd: N) {
    const d = drag<SVGGElement, unknown>()
      .clickDistance(4)
      .on('start', () => { sim?.alphaTarget(0); })
      .on('drag', (e) => { nd.fx = (nd.fx ?? nd.x ?? 0) + e.dx / currentScale(); nd.fy = (nd.fy ?? nd.y ?? 0) + e.dy / currentScale(); nd.x = nd.fx; nd.y = nd.fy; frame++; });
    select(el).call(d);
  }
  function currentScale() { const m = transform.match(/scale\(([\d.]+)\)/); return m ? +m[1] : 1; }

  // ---- interaction
  let hoverNode = $state<string | null>(null);
  let focusNode = $state<string | null>(null);
  let selected = $state<L | null>(null);
  let edgeStep = 0;
  const activeNode = $derived(hoverNode ?? focusNode);
  const adjacent = $derived.by(() => {
    const s = new Set<string>();
    if (!activeNode) return s;
    s.add(activeNode);
    for (const l of links) { if (l.source.id === activeNode) s.add(l.target.id); if (l.target.id === activeNode) s.add(l.source.id); }
    return s;
  });
  function recentre(nd: N, e?: MouseEvent | KeyboardEvent) {
    if (e && 'shiftKey' in e && e.shiftKey && nd.host_id) { navigate(hostHref(sid, nd.host_id)); return; }
    if (nd.kind === 'unknown') setQuery({ key: fpUrl(nd.fp!), host: null });
    else setQuery({ host: nd.host_id, key: null });
  }
  function nodeKey(e: KeyboardEvent, nd: N) {
    if (e.key === 'Enter') { e.preventDefault(); recentre(nd, e); }
    else if (e.key === 'e' || e.key === 'E') {
      const mine = links.filter((l) => l.source.id === nd.id || l.target.id === nd.id);
      if (mine.length) { selected = mine[edgeStep++ % mine.length]; loadEdgeDetails(selected); }
    } else if (e.key === 'Escape') { selected = null; focusNode = null; (e.target as HTMLElement).blur(); }
  }
  const tabOrder = $derived([...nodes].sort((a, b) => a.dist - b.dist || a.label.localeCompare(b.label, 'en', { numeric: true })));

  const details = new Resource<any[]>();
  function loadEdgeDetails(l: L) {
    const ids = new Set(l.links.flatMap((x: any) => x.edge_ids));
    const p: Record<string, any> = { dst_host_id: l.target.host_id, kind: l.kind, page_size: 1000 };
    if (l.source.kind === 'unknown') { p.fp = l.source.fp; p.unknown_origin = true; } else p.src_host_id = l.source.host_id;
    details.load(async () => (await api(`/scans/${sid}/edges` + qs(p))).items.filter((e: any) => ids.has(e.id)));
  }
  function selectLink(l: L) { selected = l; loadEdgeDetails(l); }

  // ---- geometry helpers
  const px = (nd: N, _f: number) => nd.x ?? 0;
  function ends(l: L, _f = 0) {
    const sx = l.source.x ?? 0, sy = l.source.y ?? 0, tx = l.target.x ?? 0, ty = l.target.y ?? 0;
    const dx = tx - sx, dy = ty - sy, len = Math.max(1, Math.hypot(dx, dy));
    const ux = dx / len, uy = dy / len;
    const r1 = l.source.r + 1, r2 = l.target.r + 3;
    return { x1: sx + ux * r1, y1: sy + uy * r1, x2: tx - ux * r2, y2: ty - uy * r2, ux, uy, len };
  }
  // edge colours (design-revision §3.3): critical keys in the Critical colour, weak in Medium, all others text.secondary
  const STROKE: Record<string, string> = { critical: 'var(--critical)', weak: 'var(--medium)', ok: 'var(--text-secondary)', good: 'var(--text-secondary)', unknown: 'var(--text-secondary)' };
  const colour = (l: L) => (l.cls === 'evidence' ? 'var(--text-secondary)' : l.cls === 'blocked' ? 'var(--text-muted)' : STROKE[l.strength ?? 'unknown']);
  const marker = (l: L) => (l.cls === 'evidence' ? 'url(#arr-ev)' : l.cls === 'blocked' ? 'url(#arr-blocked)' : `url(#arr-${l.strength ?? 'unknown'})`);
  const width = (l: L) => (l.cls === 'evidence' ? 1 : 1.5 + Math.min(l.count - 1, 3));
  const shortFp = (fp: string) => { const b = (fp ?? '').replace('SHA256:', ''); return `SHA256:${b.slice(0, 4)}…${b.slice(-4)}`; };
  function nodeLabel(nd: N) { return nd.kind === 'unknown' ? shortFp(nd.fp!) : suffix && nd.label.endsWith(suffix) ? nd.label.slice(0, -suffix.length) : nd.label; }
  const showLabel = (nd: N) => nd.dist === 0 || nodes.length <= 40 || (nd.dist === 1 && nodes.length <= 60) || activeNode === nd.id || adjacent.has(nd.id);
  const centreNode = $derived(nodes.find((x) => x.dist === 0));
  const centreText = $derived(G.key ? `Key ${shortFp(fpFromUrl(G.key))}` : centreNode ? nodeLabel(centreNode) : '…');
  const title = $derived(G.key ? `Graph around key ${shortFp(fpFromUrl(G.key))}` : `Graph around ${centreNode ? nodeLabel(centreNode) : '…'}`);
  const isolated = $derived(res.data && G.host && res.data.links.length === 0);
  let showList = $state(false);

  // ---- centre search
  let cq = $state('');
  let cres = $state<any>(null);
  let ct: number | undefined;
  function centreSearch() {
    clearTimeout(ct);
    if (cq.trim().length < 2) { cres = null; return; }
    ct = window.setTimeout(async () => { try { cres = await api('/search' + qs({ q: cq.trim(), scan: sid })); } catch { cres = null; } }, 200);
  }
  function pickCentre(p: Record<string, any>) { cq = ''; cres = null; setQuery({ host: null, key: null, ...p }); }
</script>

<PageHead title="Graph">
  {#snippet fields()}
    {#if hasCentre}<Field label="Centre" value={centreText} />{/if}
    <Field label="Hops" value={G.hops} />
    <Field label="Layer" value={G.layer === 'access' ? 'Access' : G.layer === 'evidence' ? 'Evidence' : 'Access and evidence'} />
    {#if res.data}<Field label="Nodes">{n(res.data.nodes.length)} of {n(res.data.total_nodes)}{res.data.truncated ? '+' : ''}</Field>{/if}
  {/snippet}
  {#snippet actions()}
    {#if res.data}<button class="btn" aria-pressed={showList} onclick={() => (showList = !showList)}>Edge list</button>{/if}
  {/snippet}
</PageHead>
<Notices {scan} partial />

{#if res.data?.truncated}
  <Strip role="info">Showing {res.data.nodes.length} nodes – the neighbourhood was cut at 150. Reduce hops or pick a more specific centre.</Strip>
{/if}

{#if !hasCentre}
  <section class="empty-state"><h2>Pick a centre</h2><p>Pick a host or key to see who can reach it and where it can reach.</p>
    <div class="csearch">
      <input class="input" type="search" placeholder="Centre: search host or key" aria-label="Centre: search host or key" bind:value={cq} oninput={centreSearch} />
      {#if cres}
        <div class="popover cl">
          {#each cres.hosts as h}<button onclick={() => pickCentre({ host: h.host_id })}><span>{h.display_name}</span></button>{/each}
          {#each cres.keys as k}<button onclick={() => pickCentre({ key: fpUrl(k.fp) })}><Fp fp={k.fp} copy={false} /><span class="meta secondary">{k.label || k.comment || ''}</span></button>{/each}
          {#if !cres.hosts.length && !cres.keys.length}<p class="meta secondary none">Nothing matches "{cq}" in scan #{sid}.</p>{/if}
        </div>
      {/if}
    </div></section>
{:else if res.error}
  <ErrorPanel thing="the graph" message={res.error} retry={load} />
{:else}
  <div class="grid-2">
    <section class="panel flush gp">
      <div class="toolbar">
        <div class="csearch">
          <input class="input" type="search" placeholder="Centre: search host or key" aria-label="Centre: search host or key" bind:value={cq} oninput={centreSearch} />
          {#if cres}
            <div class="popover cl">
              {#each cres.hosts as h}<button onclick={() => pickCentre({ host: h.host_id })}><span>{h.display_name}</span><span class="meta secondary num">{h.ips?.[0] ?? ''}</span></button>{/each}
              {#each cres.keys as k}<button onclick={() => pickCentre({ key: fpUrl(k.fp) })}><Fp fp={k.fp} copy={false} /><span class="meta secondary">{k.label || k.comment || ''}</span></button>{/each}
              {#if !cres.hosts.length && !cres.keys.length}<p class="meta secondary none">Nothing matches "{cq}" in scan #{sid}.</p>{/if}
            </div>
          {/if}
        </div>
        <div class="seg" role="radiogroup" aria-label="Hops">
          {#each [1, 2] as h}<button role="radio" aria-checked={G.hops === h} onclick={() => setQuery({ hops: h === 1 ? null : h })}>Hops: {h}</button>{/each}
        </div>
        <div class="seg" role="radiogroup" aria-label="Layer">
          {#each [['access', 'Access'], ['evidence', 'Evidence'], ['both', 'Both']] as [v, l]}<button role="radio" aria-checked={G.layer === v} onclick={() => setQuery({ layer: v === 'access' ? null : v })}>{l}</button>{/each}
        </div>
        <span class="spacer"></span>
        {#if res.data}<button class="btn ghost" onclick={fit}>Fit</button>{/if}
      </div>
      {#if isolated}<div class="iso"><Strip role="info">{centreNode?.label} has no access edges to or from other scanned hosts.</Strip></div>{/if}
      {#if !res.data}<div class="loading secondary">Laying out the graph…</div>{/if}
      <svg bind:this={svg} class="g" viewBox="0 0 {WIDTH} {HEIGHT}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="{title}: {nodes.length} nodes, {links.length} edges. Use the edge list for a table.">
        <defs>
          {#each ['critical', 'weak', 'ok', 'good', 'unknown'] as s}
            <marker id="arr-{s}" viewBox="0 0 6 6" refX="5" refY="3" markerWidth="6" markerHeight="6" markerUnits="userSpaceOnUse" orient="auto"><path d="M0,0 L6,3 L0,6 z" fill={STROKE[s]} /></marker>
          {/each}
          <marker id="arr-blocked" viewBox="0 0 6 6" refX="5" refY="3" markerWidth="6" markerHeight="6" markerUnits="userSpaceOnUse" orient="auto"><path d="M0,0 L6,3 L0,6 z" fill="var(--text-muted)" /></marker>
          <marker id="arr-ev" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="8" markerHeight="8" markerUnits="userSpaceOnUse" orient="auto"><path d="M1,1 L7,4 L1,7" fill="none" stroke="var(--text-secondary)" stroke-width="1" /></marker>
        </defs>
        <g bind:this={viewport} transform={transform}>
                    {#each links as l (l.id)}
            {@const e = ends(l, frame)}
            {@const dim = activeNode && !(l.source.id === activeNode || l.target.id === activeNode)}
            {@const mx = (e.x1 + e.x2) / 2}
            {@const my = (e.y1 + e.y2) / 2}
            <g class="link" class:dim class:sel={selected?.id === l.id} onclick={() => selectLink(l)} role="presentation">
              <line class="hit" x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2} />
              {#if l.cls === 'unknown'}
                <line x1={e.x1} y1={e.y1} x2={e.x1 + e.ux * 12} y2={e.y1 + e.uy * 12} stroke={colour(l)} stroke-width={width(l)} stroke-dasharray="2 2" />
                <line x1={e.x1 + e.ux * 12} y1={e.y1 + e.uy * 12} x2={e.x2} y2={e.y2} stroke={colour(l)} stroke-width={width(l)} marker-end={marker(l)} />
              {:else}
                <line x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2} stroke={colour(l)} stroke-width={width(l)} marker-end={marker(l)}
                  stroke-dasharray={l.cls === 'evidence' ? '4 3' : undefined} class:blocked={l.cls === 'blocked'} />
              {/if}
              {#if l.cls === 'restricted'}<circle cx={mx} cy={my} r="3" class="mid" stroke={colour(l)} />{/if}
              {#if l.cls === 'blocked'}<line x1={mx - e.uy * 4} y1={my + e.ux * 4} x2={mx + e.uy * 4} y2={my - e.ux * 4} stroke="var(--text-muted)" stroke-width="1.5" />{/if}
              {#if l.count > 1 && (activeNode === l.source.id || activeNode === l.target.id || selected?.id === l.id)}<text x={mx + 4} y={my - 4} class="cnt">×{l.count}</text>{/if}
            </g>
          {/each}
          {#each nodes as nd (nd.id)}
            {@const dim = activeNode && !adjacent.has(nd.id)}
            {@const ns = nd.status && NOT_SCANNED.concat(['unreachable', 'timeout', 'auth_failed', 'hostkey_mismatch', 'hostkey_unknown']).includes(nd.status)}
            <g class="node" class:dim transform="translate({px(nd, frame)},{nd.y ?? 0})" use:dragAction={nd}
              tabindex={-1} role="button" aria-label="{nodeLabel(nd)}{nd.status ? ', ' + (STATUS_LABEL[nd.status] ?? nd.status) : ''}"
              onclick={(e) => recentre(nd, e)} onkeydown={(e) => nodeKey(e, nd)}
              onmouseenter={() => (hoverNode = nd.id)} onmouseleave={() => (hoverNode = null)} onfocus={() => (focusNode = nd.id)} onblur={() => (focusNode = null)}>
              {#if nd.kind === 'unknown'}
                <rect x="-7" y="-7" width="14" height="14" transform="rotate(45)" class="unk" />
              {:else}
                {#if nd.dist === 0}<circle r={nd.r + 4} class="centre" />{/if}
                <circle r={nd.r} class="host" class:ns />
                {#if nd.status === 'partial'}<path d="M0,{-nd.r} A{nd.r},{nd.r} 0 0 1 0,{nd.r} Z" class="half" />{/if}
                {#if nd.sev === 'critical' || nd.sev === 'high'}
                  <g class="sm sg-{nd.sev}" transform="translate({nd.r * 0.7},{-nd.r - 14})">
                    <rect class="smbg" x="-2" y="-2" width="16" height="16" rx="3" />
                    {#each [0, 1, 2, 3] as i}<rect x={i * 3 + 0.5} y={12 - (i + 1) * 3} width="2" height={(i + 1) * 3} fill-opacity={i < (nd.sev === 'critical' ? 4 : 3) ? 1 : 0.25} />{/each}
                  </g>
                {/if}
              {/if}
              {#if showLabel(nd)}
                {@const t = nodeLabel(nd)}
                <rect class="plate" x={nd.r + 4} y="-8" width={t.length * 6.7 + 6} height="16" rx="2" />
                <text class="lbl" class:ns x={nd.r + 7} y="4">{t}</text>
              {/if}
            </g>
          {/each}
        </g>
      </svg>
      <div class="sr-only">
        {#each tabOrder as nd}<button onfocus={() => (focusNode = nd.id)} onblur={() => (focusNode = null)} onclick={() => recentre(nd)} onkeydown={(e) => nodeKey(e, nd)}>{nodeLabel(nd)} (distance {nd.dist}); Enter re-centres, E steps through its edges</button>{/each}
      </div>
      <p class="legend meta secondary">
        <span><svg width="28" height="8" aria-hidden="true"><line x1="0" y1="4" x2="28" y2="4" stroke="var(--text-secondary)" stroke-width="1.5" /></svg> access</span>
        <span><svg width="28" height="8" aria-hidden="true"><line x1="0" y1="4" x2="28" y2="4" stroke="var(--text-secondary)" stroke-dasharray="4 3" /></svg> evidence</span>
        <span><svg width="28" height="10" aria-hidden="true"><line x1="0" y1="5" x2="28" y2="5" stroke="var(--text-muted)" stroke-width="1.5" /><line x1="14" y1="1" x2="14" y2="9" stroke="var(--text-muted)" stroke-width="1.5" /></svg> blocked</span>
        <span><svg width="28" height="10" aria-hidden="true"><line x1="0" y1="5" x2="28" y2="5" stroke="var(--text-secondary)" stroke-width="1.5" /><circle cx="14" cy="5" r="3" fill="var(--bg-surface)" stroke="var(--text-secondary)" /></svg> from= restricted</span>
        <span><svg width="14" height="14" aria-hidden="true"><rect x="3" y="3" width="8" height="8" transform="rotate(45 7 7)" fill="var(--bg-surface)" stroke="var(--text-secondary)" stroke-dasharray="2 1.5" /></svg> unknown origin</span>
        <span><svg width="28" height="8" aria-hidden="true"><line x1="0" y1="4" x2="28" y2="4" stroke="var(--critical)" stroke-width="1.5" /></svg> critical key</span>
        <span><svg width="28" height="8" aria-hidden="true"><line x1="0" y1="4" x2="28" y2="4" stroke="var(--medium)" stroke-width="1.5" /></svg> weak key</span>
        <span><svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true" class="sg-critical">{#each [0, 1, 2, 3] as i}<rect x={i * 3 + 0.5} y={12 - (i + 1) * 3} width="2" height={(i + 1) * 3} fill="currentColor" />{/each}</svg> host with critical findings</span>
        {#if suffix}<span>Hidden suffix: <span class="mono">{suffix}</span></span>{/if}
        <span class="muted">Click a node to centre on it (Shift+click opens the host), drag to pin, scroll to zoom.</span>
      </p>
    </section>

    <aside class="panel det">
      <h2 class="section-title">Details</h2>
      {#if !selected}
        <p class="secondary dense">Click a node to centre on it, or an edge to see its keys.</p>
      {:else}
        <p class="sel-t">{#if selected.source.kind === 'unknown'}<span class="mono">{shortFp(selected.source.fp)}</span>{:else}{selected.source.label}{/if} → {selected.target.label}</p>
        <dl class="dl">
          <dt>Kind</dt><dd>{selected.kind}</dd>
          <dt>Status</dt><dd>{EDGE_STATUS[selected.status] ?? selected.status}</dd>
          <dt>Effective</dt><dd>{selected.effective ? 'yes' : 'no'}</dd>
          <dt>Edges</dt><dd class="num">{selected.count}</dd>
        </dl>
        {#if details.data}
          <ul class="dl-list">
            {#each details.data as e (e.id)}
              <li>
                <div class="dense">{e.src ?? 'unknown'}{e.src_user ? ':' + e.src_user : ''} → {e.dst}{e.dst_user ? ':' + e.dst_user : ''}</div>
                {#if e.fp}<div class="row"><Fp fp={e.fp} href={keyHref(sid, e.fp)} /><StrengthChip strength={e.strength} /></div>{/if}
                {#if e.authorized_file}<div class="mono meta secondary">{fileLine(e.authorized_file, e.authorized_line)}</div>{/if}
                {#if e.evidence_file}<div class="meta secondary">{SOURCE_LABEL[e.evidence_source] ?? e.evidence_source} <span class="mono">{fileLine(e.evidence_file, e.evidence_line)}</span></div>{/if}
                {#if e.flags.length}<div class="chips">{#each e.flags as f}<span class="kchip">{FLAG_LABEL[f] ?? f}</span>{/each}</div>{/if}
              </li>
            {/each}
          </ul>
        {:else if details.error}<ErrorPanel thing="edge details" message={details.error} />{/if}
        {#if selected.target.host_id}<p><a class="btn" href={hostHref(sid, selected.target.host_id, 'access')}>Open {selected.target.label}</a></p>{/if}
      {/if}
    </aside>
  </div>

  {#if showList && res.data}
    <section class="panel flush">
      <header><h2 class="section-title">Edge list</h2></header>
      <div class="table-wrap"><table class="t">
        <thead><tr><th>From</th><th>To</th><th>Kind</th><th>Status</th><th>Strength</th><th class="r">Edges</th></tr></thead>
        <tbody>{#each links as l (l.id)}<tr>
          <td class="ent">{nodeLabel(l.source)}</td><td>{l.target.label}</td><td>{l.kind}</td>
          <td>{EDGE_STATUS[l.status] ?? l.status}{l.effective ? '' : ' (not effective)'}</td><td>{#if l.kind === 'access'}<StrengthChip strength={l.strength} />{:else}–{/if}</td>
          <td class="r num"><button class="btn ghost small" onclick={() => selectLink(l)}>{l.count}</button></td>
        </tr>{/each}</tbody>
      </table></div>
    </section>
  {/if}
{/if}

<style>
  .gp { position: relative; overflow: hidden; }
  .g { width: 100%; height: min(680px, calc(100vh - 280px)); min-height: 420px; display: block; cursor: grab; background: var(--bg-surface); }
  .iso { position: absolute; left: var(--s4); right: var(--s4); top: var(--s4); z-index: 2; }
  .loading { position: absolute; left: 50%; top: 40%; transform: translate(-50%, -50%); }
  .hit { stroke: transparent; stroke-width: 10; cursor: pointer; }
  .link line.blocked { opacity: .5; }
  .link .mid { fill: var(--bg-surface); stroke-width: 1.5; }
  .link.sel line:not(.hit) { filter: drop-shadow(0 0 2px var(--accent)); }
  .cnt { font: 500 12px var(--sans); fill: var(--text-primary); }
  .dim { opacity: .2; }
  .node { cursor: pointer; }
  .node:focus { outline: none; }
  .node:focus .host, .node:focus .unk { stroke-width: 3; }
  .host { fill: var(--bg-surface); stroke: var(--text-primary); stroke-width: 1.5; }
  .host.ns { stroke-dasharray: 3 2; stroke: var(--text-muted); }
  .half { fill: var(--text-muted); }
  .centre { fill: none; stroke: var(--accent); stroke-width: 2; }
  .unk { fill: var(--bg-surface); stroke: var(--text-secondary); stroke-width: 1.5; stroke-dasharray: 3 2; }
  .plate { fill: var(--bg-surface); opacity: .8; }
  .lbl { font: 400 12px var(--sans); fill: var(--text-primary); }
  .lbl.ns { fill: var(--text-muted); }
  .sg-critical { fill: var(--critical); color: var(--critical); }
  .sg-high { fill: var(--high); color: var(--high); }
  .smbg { fill: var(--bg-surface); fill-opacity: 1; }
  .sel-t { font-weight: 600; }
  .legend { display: flex; flex-wrap: wrap; gap: var(--s4); padding: var(--s3) var(--s4); border-top: 1px solid var(--border-subtle); margin: 0; align-items: center; }
  .legend span { display: inline-flex; gap: var(--s2); align-items: center; }
  .det { display: flex; flex-direction: column; gap: var(--s3); }
  .dl-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: var(--s3); }
  .dl-list li { border-top: 1px solid var(--border-subtle); padding-top: var(--s3); display: flex; flex-direction: column; gap: var(--s2); }
  .csearch { position: relative; }
  .csearch .input { width: 220px; }
  .cl { top: 36px; left: 0; min-width: 320px; max-height: 320px; overflow: auto; padding: var(--s2) 0; }
  .cl button { all: unset; box-sizing: border-box; display: flex; gap: var(--s3); align-items: center; width: 100%; height: 32px; padding: 0 var(--s4); cursor: pointer; }
  .cl button:hover, .cl button:focus-visible { background: var(--bg-hover); }
  .none { padding: var(--s3) var(--s4); }
</style>
