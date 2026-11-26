<script lang="ts">
  // Scan detail - crawl tree (design §4.4, design-revision §5.8): entry -> children by discovery, plus references that
  // led to no new host. A filter finds a host by name or IP, also inside collapsed branches (check-9 N3).
  import { tick } from 'svelte';
  import { api, qs } from '../lib/api';
  import { Resource } from '../lib/state.svelte';
  import { endTrunc, fileLine, midTrunc, n, NOT_SCANNED, privilege, SOURCE_LABEL, STATUS_LABEL } from '../lib/format';
  import { hostHref } from '../lib/links';
  import PageHead from '../components/PageHead.svelte';
  import Field from '../components/Field.svelte';
  import Notices from '../components/Notices.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import HopChain from '../components/HopChain.svelte';
  import Strip from '../components/Strip.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';
  import Skeleton from '../components/Skeleton.svelte';

  let { scan }: { scan: any } = $props();
  const sid = scan.id;
  const res = new Resource<any>();
  const det = new Resource<any>();
  const load = () => { res.load(() => api(`/scans/${sid}/crawl`)); det.load(() => api(`/scans/${sid}`)); };
  load();

  let statusFilter = $state('all');
  // ---- text filter (name or IP): matching rows and their ancestors are shown, whatever is collapsed
  let fq = $state('');
  const needle = $derived(fq.trim().toLowerCase());
  let ips = $state<Map<number, string[]>>(new Map());
  let ipsLoading = false;
  async function loadIps() {
    if (ipsLoading || ips.size) return;
    ipsLoading = true;
    const m = new Map<number, string[]>();
    try {
      for (let page = 1; ; page++) {
        const r = await api(`/scans/${sid}/hosts` + qs({ page, page_size: 1000 }));
        for (const h of r.items) m.set(h.host_id, h.ips ?? []);
        if (page * 1000 >= r.total) break;
      }
      ips = m;
    } catch { /* names still match */ } finally { ipsLoading = false; }
  }
  function hit(nd: Node): boolean {
    if (!needle) return false;
    if (nd.kind === 'ref') return String(nd.r.value ?? '').toLowerCase().includes(needle);
    const h = nd.h;
    return h.display_name.toLowerCase().includes(needle) || String(h.via?.value ?? '').toLowerCase().includes(needle)
      || (ips.get(h.host_id) ?? []).some((ip) => ip.includes(needle));
  }
  function subtreeHit(nd: Node): boolean { return hit(nd) || nd.children.some(subtreeHit); }
  let showRefs = $state(true);
  let expanded = $state<Set<string>>(new Set());
  let attemptsOpen = $state<Set<number>>(new Set());
  let initDone = false;

  type Node = { key: string; depth: number; kind: 'host' | 'ref'; h?: any; r?: any; children: Node[] };
  const OUTCOME_CHIP: Record<string, string> = { excluded: 'Excluded – seen only', out_of_scope: 'Out of scope', max_depth: 'Depth limit',
    max_hosts: 'Host limit', unresolvable: 'Unresolvable', already: 'Already found', alias: 'Alias of' };

  const tree = $derived.by(() => {
    if (!res.data) return [] as Node[];
    const hosts = res.data.hosts as any[];
    const byParent = new Map<number | null, any[]>();
    for (const h of hosts) {
      const p = h.parent_host_id ?? null;
      if (!byParent.has(p)) byParent.set(p, []);
      byParent.get(p)!.push(h);
    }
    const refsBy = new Map<number, any[]>();
    for (const r of res.data.references as any[]) {
      if (!refsBy.has(r.from_host_id)) refsBy.set(r.from_host_id, []);
      refsBy.get(r.from_host_id)!.push(r);
    }
    const order = (a: any, b: any) => (a.depth ?? 0) - (b.depth ?? 0) || a.display_name.localeCompare(b.display_name, 'en', { numeric: true });
    const build = (h: any, depth: number): Node => {
      const kids = (byParent.get(h.host_id) ?? []).sort(order).map((c) => build(c, depth + 1));
      const refs = (refsBy.get(h.host_id) ?? []).map((r) => ({ key: `r${r.id}`, depth: depth + 1, kind: 'ref' as const, r, children: [] }));
      return { key: `h${h.host_id}`, depth, kind: 'host', h, children: [...kids, ...refs] };
    };
    return (byParent.get(null) ?? []).sort(order).map((h) => build(h, 0));
  });

  $effect(() => {
    if (tree.length && !initDone) {
      initDone = true;
      const s = new Set<string>();
      const big = res.data.hosts.length > 200;
      const walk = (nd: Node) => { if (!big || nd.depth < 1) s.add(nd.key); nd.children.forEach(walk); };
      tree.forEach(walk);
      expanded = s;
    }
  });

  function visible(nd: Node): boolean {
    if (nd.kind === 'ref') {
      if (!showRefs) return false;
      return statusFilter === 'all' || statusFilter === 'not_scanned';
    }
    return true;
  }
  function matches(nd: Node): boolean {
    if (statusFilter === 'all') return true;
    if (nd.kind === 'ref') return statusFilter === 'not_scanned';
    const st = nd.h.status;
    if (statusFilter === 'not_scanned') return NOT_SCANNED.includes(st);
    return st === statusFilter;
  }
  function subtreeMatches(nd: Node): boolean { return matches(nd) || nd.children.some(subtreeMatches); }

  const rows = $derived.by(() => {
    const out: { nd: Node; hasKids: boolean; hit?: boolean }[] = [];
    if (needle) {
      ips; // re-run when the addresses arrive
      const walkF = (nd: Node) => {
        if (!visible(nd) || !subtreeMatches(nd) || !subtreeHit(nd)) return;
        const kids = nd.children.filter((c) => visible(c) && subtreeMatches(c) && subtreeHit(c));
        out.push({ nd, hasKids: kids.length > 0, hit: hit(nd) });
        kids.forEach(walkF);
      };
      tree.forEach(walkF);
      return out;
    }
    const walk = (nd: Node) => {
      if (!visible(nd) || !subtreeMatches(nd)) return;
      const kids = nd.children.filter((c) => visible(c) && subtreeMatches(c));
      out.push({ nd, hasKids: kids.length > 0 });
      if (expanded.has(nd.key)) kids.forEach(walk);
    };
    tree.forEach(walk);
    return out;
  });
  const hits = $derived(needle ? rows.filter((r) => r.hit).length : 0);

  // Virtualisation (design §4.4: at 2,000 hosts the tree is virtualised). Above VIRT_MIN rows only the rows near the
  // viewport are in the DOM; spacer rows keep the scroll height, so every host stays reachable by scrolling,
  // by expand/collapse and by the arrow keys. Row heights are measured (an open attempts list makes a row taller).
  const VIRT_MIN = 400;
  const OVERSCAN = 800;
  const virt = $derived(rows.length > VIRT_MIN);
  let rowH = $state(33);
  const measured = new Map<string, number>();
  let mver = $state(0);
  let scrollY = $state(0);
  let vh = $state(typeof window !== 'undefined' ? window.innerHeight : 900);
  let bodyTop = $state(0);
  let tbodyEl = $state<HTMLElement | undefined>();
  const offsets = $derived.by(() => {
    mver;
    const o = new Float64Array(rows.length + 1);
    for (let i = 0; i < rows.length; i++) o[i + 1] = o[i] + (measured.get(rows[i].nd.key) ?? rowH);
    return o;
  });
  function lowerBound(o: Float64Array, v: number): number {
    let lo = 0, hi = o.length - 1;
    while (lo < hi) { const m = (lo + hi) >> 1; if (o[m + 1] <= v) lo = m + 1; else hi = m; }
    return lo;
  }
  const range = $derived.by((): [number, number] => {
    if (!virt) return [0, rows.length];
    const top = scrollY - bodyTop - OVERSCAN, bottom = scrollY - bodyTop + vh + OVERSCAN;
    const a = Math.max(0, lowerBound(offsets, Math.max(0, top)));
    const b = Math.min(rows.length, lowerBound(offsets, Math.max(0, bottom)) + 1);
    return [a, Math.max(a, b)];
  });
  const shown = $derived(rows.slice(range[0], range[1]).map((r, i) => ({ ...r, idx: range[0] + i })));
  const isOpen = (key: string) => !!needle || expanded.has(key);
  function onScroll() {
    scrollY = window.scrollY;
    vh = window.innerHeight;
    if (tbodyEl) bodyTop = tbodyEl.getBoundingClientRect().top + window.scrollY;   // the top spacer is inside tbody
  }
  $effect(() => {
    shown; // after every render of the window: measure the rendered rows
    tick().then(() => {
      if (!tbodyEl) return;
      let changed = false;
      for (const tr of tbodyEl.querySelectorAll<HTMLElement>('tr[data-key]')) {
        const h = tr.getBoundingClientRect().height;
        const k = tr.dataset.key!;
        if (h > 0 && Math.abs((measured.get(k) ?? rowH) - h) > 0.5) { measured.set(k, h); changed = true; }
      }
      const first = tbodyEl.querySelector<HTMLElement>('tr[data-key]');
      if (first && !changed && measured.size > 0) {
        const typical = [...measured.values()].sort((x, y) => x - y)[Math.floor(measured.size / 2)];
        if (Math.abs(typical - rowH) > 0.5) { rowH = typical; changed = true; }
      }
      if (changed) mver++;
      onScroll();
    });
  });
  async function focusRow(i: number) {
    if (i < 0 || i >= rows.length) return;
    let el = document.querySelector<HTMLElement>(`tr[data-idx="${i}"]`);
    if (!el) {
      window.scrollTo(0, bodyTop + offsets[i] - vh / 2);
      onScroll();
      await tick();
      el = document.querySelector<HTMLElement>(`tr[data-idx="${i}"]`);
    }
    el?.focus();
  }

  function toggle(key: string) {
    const s = new Set(expanded);
    if (s.has(key)) s.delete(key); else s.add(key);
    expanded = s;
  }
  function expandAll() { const s = new Set<string>(); const w = (nd: Node) => { s.add(nd.key); nd.children.forEach(w); }; tree.forEach(w); expanded = s; }
  function collapseAll() { expanded = new Set(); }
  function keyNav(e: KeyboardEvent, key: string, hasKids: boolean, idx: number) {
    if (e.key === 'ArrowRight' && hasKids && !expanded.has(key)) { e.preventDefault(); toggle(key); }
    else if (e.key === 'ArrowLeft' && expanded.has(key)) { e.preventDefault(); toggle(key); }
    else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); focusRow(idx + (e.key === 'ArrowDown' ? 1 : -1)); }
    else if (e.key === 'Home' || e.key === 'End') { e.preventDefault(); focusRow(e.key === 'Home' ? 0 : rows.length - 1); }
  }
  const hostIds = $derived(Object.fromEntries((res.data?.hosts ?? []).map((h: any) => [h.display_name, h.host_id])));
  const p = $derived(det.data?.params ?? {});
  const unresolved = $derived(res.data?.unresolved_hashed_total ?? 0);
  const scanned = $derived((res.data?.hosts ?? []).filter((h: any) => !NOT_SCANNED.includes(h.status)).length);
</script>

<svelte:window onscroll={onScroll} onresize={onScroll} />

<PageHead title="Crawl tree">
  {#snippet fields()}
    <Field label="Scan">Scan #{sid} <span class="secondary">{scan.label || 'unlabelled'}</span></Field>
    <Field label="Max depth" value={p.max_depth ?? '–'} />
    <Field label="Max hosts" value={n(p.max_hosts)} />
    <Field label="Hashed known_hosts">{#if unresolved > 0}<a href="/s/{sid}/hosts?sort=unresolved_hashed">{n(unresolved)} hashed known_hosts {unresolved === 1 ? 'entry' : 'entries'} could not be matched to any host.</a>{:else}every hashed known_hosts entry was matched{/if}</Field>
  {/snippet}
</PageHead>
<Notices {scan} />

{#if res.error}
  <ErrorPanel thing="the crawl tree" message={res.error} retry={load} />
{:else if !res.data}
  {#if res.slow}<Skeleton />{/if}
{:else}
  {#if scan.status === 'aborted' && res.data.hosts.length === 0}
    <Strip role="error">Scan #{sid} was aborted before any host was scanned: {scan.counts?.error ?? 'no error recorded'}.</Strip>
  {:else if scanned === 1}
    <Strip role="info">Only the entry point was found; it has no known_hosts/ssh config references. Add seeds to scan more.</Strip>
  {/if}
  <section class="panel flush">
    <div class="toolbar">
      <span class="fbox">
        <svg class="lens" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="4.25" fill="none" stroke="currentColor" stroke-width="1.5" /><path d="M10.2 10.2 13.5 13.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" /></svg>
        <input class="input fi" type="search" placeholder="Filter by host name or IP" aria-label="Filter by host name or IP" bind:value={fq} oninput={loadIps} />
      </span>
      <label class="ctl">Status
        <select class="select" bind:value={statusFilter}>
          <option value="all">All</option><option value="ok">OK</option><option value="partial">Partial</option>
          <option value="unreachable">Unreachable</option><option value="hostkey_mismatch">Host key changed</option><option value="not_scanned">Not scanned</option>
        </select>
      </label>
      <label class="check"><input type="checkbox" bind:checked={showRefs} />Show not-scanned references</label>
      <span class="spacer"></span>
      <button class="btn ghost" onclick={expandAll} disabled={!!needle}>Expand all</button>
      <button class="btn ghost" onclick={collapseAll} disabled={!!needle}>Collapse all</button>
    </div>
    <div class="tfoot top" aria-live="polite"><span>{n(rows.length)} {rows.length === 1 ? 'row' : 'rows'} shown</span>{#if needle}<span>{n(hits)} {hits === 1 ? 'match' : 'matches'} for “{fq.trim()}”</span>{/if}</div>
    <div class="table-wrap">
      <table class="t tree" role="treegrid" aria-label="Crawl tree" aria-rowcount={rows.length + 1}>
        <thead><tr><th>Host</th><th class="r">Depth</th><th>Status</th><th>Privilege</th><th>Route</th><th>Discovered via</th></tr></thead>
        <tbody bind:this={tbodyEl}>
          {#if virt && range[0] > 0}<tr class="spacer" aria-hidden="true"><td colspan="6" style:height="{offsets[range[0]]}px"></td></tr>{/if}
          {#each shown as { nd, hasKids, idx, hit } (nd.key)}
            {#if nd.kind === 'host'}
              {@const h = nd.h}
              {@const failed = (h.route_attempts ?? []).filter((a: any) => a.error)}
              <tr data-tree data-key={nd.key} data-idx={idx} aria-rowindex={idx + 2} tabindex="0" aria-level={nd.depth + 1} aria-expanded={hasKids ? isOpen(nd.key) : undefined}
                onkeydown={(e) => keyNav(e, nd.key, hasKids, idx)} class:ns={NOT_SCANNED.includes(h.status)} class:hit>
                <td class="hcell">
                  <span class="ind" style:width="{nd.depth * 16}px" aria-hidden="true"></span>
                  {#if hasKids}<button class="tw" aria-label={isOpen(nd.key) ? 'Collapse' : 'Expand'} disabled={!!needle} onclick={() => toggle(nd.key)}><svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d={isOpen(nd.key) ? 'M3 4.5 6 7.5 9 4.5' : 'M4.5 3 7.5 6 4.5 9'} fill="none" stroke="currentColor" stroke-width="1.5" /></svg></button>{:else}<span class="tw"></span>{/if}
                  {#if NOT_SCANNED.includes(h.status)}<span class="hn muted" title={h.display_name}>{endTrunc(h.display_name, 40)}</span>{:else}<a class="hn" href={hostHref(sid, h.host_id)} title={h.display_name}>{endTrunc(h.display_name, 40)}</a>{/if}
                </td>
                <td class="r num">{h.depth ?? '–'}</td>
                <td>{#if NOT_SCANNED.includes(h.status)}<span class="state muted">{OUTCOME_CHIP[h.status] ?? STATUS_LABEL[h.status] ?? h.status}</span>{:else}<StatusBadge status={h.status} />{/if}</td>
                <td class="nowrap">{NOT_SCANNED.includes(h.status) ? '–' : privilege(h.privilege)}</td>
                <td class="route">
                  <div class="rline">
                    <span class="chain">{#if NOT_SCANNED.includes(h.status)}<span class="muted">seen only</span>{:else}<HopChain route={h.route} links={hostIds} scan={sid} />{/if}</span>
                    {#if failed.length || h.status === 'unreachable' || h.status === 'timeout'}
                      <button class="btn ghost small att-btn" aria-expanded={attemptsOpen.has(h.host_id)} onclick={() => { const s = new Set(attemptsOpen); s.has(h.host_id) ? s.delete(h.host_id) : s.add(h.host_id); attemptsOpen = s; }}>{failed.length} failed attempt{failed.length !== 1 ? 's' : ''}<svg class="chev" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d={attemptsOpen.has(h.host_id) ? 'M3 7.5 6 4.5 9 7.5' : 'M3 4.5 6 7.5 9 4.5'} fill="none" stroke="currentColor" stroke-width="1.5" /></svg></button>
                    {/if}
                  </div>
                  {#if attemptsOpen.has(h.host_id)}
                    <ul class="att" aria-label="Route attempts">{#each h.route_attempts as a}<li><span class="ar">{(a.route ?? []).join(' → ')}</span> <span class="mono" class:err={a.error}>{a.error ?? 'ok'}</span></li>{/each}</ul>
                  {/if}
                </td>
                <td class="mono via" title={h.via?.parent ? `${h.via.parent} ${fileLine(h.via.file, h.via.line)}${h.via.source === 'known_hosts_hashed' ? ' (hashed)' : ''}` : ''}>
                  {#if h.via?.parent}{midTrunc(fileLine(h.via.file, h.via.line), 26)}{#if h.via.source === 'known_hosts_hashed'} <span class="secondary sans">(hashed)</span>{/if}{:else}<span class="secondary sans">{h.via?.source === 'entry' ? 'entry' : h.via?.source ?? '–'}</span>{/if}
                </td>
              </tr>
            {:else}
              {@const r = nd.r}
              <tr data-tree data-key={nd.key} data-idx={idx} aria-rowindex={idx + 2} tabindex="0" aria-level={nd.depth + 1} onkeydown={(e) => keyNav(e, nd.key, false, idx)} class="ns" class:hit>
                <td class="hcell"><span class="ind" style:width="{nd.depth * 16}px" aria-hidden="true"></span><span class="tw"></span><span class="hn muted" title={r.value}>{endTrunc(r.value, 40)}</span></td>
                <td></td>
                <td><span class="state muted">{r.outcome === 'alias' ? `Alias of ${r.target ?? '?'}` : OUTCOME_CHIP[r.outcome] ?? r.outcome}</span></td>
                <td></td>
                <td class="muted route-ref">{SOURCE_LABEL[r.source] ?? r.source}{#if r.username}<span class="ru">{r.username}</span>{/if}</td>
                <td class="mono via muted" title={fileLine(r.file, r.line)}>{midTrunc(fileLine(r.file, r.line), 26)}</td>
              </tr>
            {/if}
          {:else}
            <tr><td class="empty" colspan="6">{needle ? `No host or reference in scan #${sid} matches “${fq.trim()}”.` : 'No rows match these filters.'}</td></tr>
          {/each}
          {#if virt && range[1] < rows.length}<tr class="spacer" aria-hidden="true"><td colspan="6" style:height="{offsets[rows.length] - offsets[range[1]]}px"></td></tr>{/if}
        </tbody>
      </table>
    </div>
  </section>
{/if}

<style>
  .fbox { position: relative; display: inline-flex; }
  .lens { position: absolute; left: 10px; top: 8px; color: var(--text-muted); pointer-events: none; }
  .fi { width: 260px; padding-left: 34px; }
  .tfoot.top { border-top: 0; border-bottom: 1px solid var(--border-subtle); min-height: 36px; justify-content: flex-start; gap: var(--s6); }
  .hcell { white-space: nowrap; }
  .hn { font-weight: 500; }
  .ind { display: inline-block; height: 1px; vertical-align: middle; }
  .tree td { padding-top: 6px; padding-bottom: 6px; }
  tr.ns .hn { font-weight: 400; }
  .tw { display: inline-flex; width: 24px; height: 24px; align-items: center; justify-content: center; border: 0; background: none;
    color: var(--text-secondary); cursor: pointer; vertical-align: middle; border-radius: var(--r1); padding: 0; }
  button.tw:hover { background: var(--bg-hover); }
  button.tw:disabled { cursor: default; color: var(--text-muted); }
  tr.ns td { color: var(--text-secondary); }
  tr.hit { background: var(--bg-selected); }
  tr.hit .hn { color: var(--text-primary); }
  .sans { font-family: var(--sans); }
  /* Route and Discovered via share the remaining width and truncate (full value in title) */
  .via { white-space: nowrap; width: 40%; max-width: 0; min-width: 150px; overflow: hidden; text-overflow: ellipsis; }
  .route { width: 60%; max-width: 0; min-width: 150px; }
  .rline { display: flex; flex-wrap: wrap; align-items: center; column-gap: var(--s3); min-width: 0; }
  .chain { min-width: 0; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .rline .btn { flex: none; gap: var(--s2); }
  .route-ref { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 0; }
  .ru { margin-left: var(--s3); }
  .att { list-style: none; margin: var(--s2) 0 0; padding: 0; font-size: 12px; line-height: 16px; }
  .att li { overflow-wrap: anywhere; }
  .att .ar { color: var(--text-secondary); }
  .att .err { color: var(--high); }
  tr.spacer td { padding: 0; border: 0; }
  tr.spacer:hover { background: none; }
  tr[data-tree]:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
</style>
