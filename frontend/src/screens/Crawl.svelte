<script lang="ts">
  // Scan detail - crawl tree (design §4.4): entry -> children by discovery, plus references that led to no new host.
  import { api } from '../lib/api';
  import { Resource } from '../lib/state.svelte';
  import { fileLine, n, NOT_SCANNED, privilege, SOURCE_LABEL, STATUS_LABEL } from '../lib/format';
  import { hostHref } from '../lib/links';
  import PageHead from '../components/PageHead.svelte';
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
    const out: { nd: Node; hasKids: boolean }[] = [];
    const walk = (nd: Node) => {
      if (!visible(nd) || !subtreeMatches(nd)) return;
      const kids = nd.children.filter((c) => visible(c) && subtreeMatches(c));
      out.push({ nd, hasKids: kids.length > 0 });
      if (expanded.has(nd.key)) kids.forEach(walk);
    };
    tree.forEach(walk);
    return out;
  });
  const MAXROWS = 1500;

  function toggle(key: string) {
    const s = new Set(expanded);
    if (s.has(key)) s.delete(key); else s.add(key);
    expanded = s;
  }
  function expandAll() { const s = new Set<string>(); const w = (nd: Node) => { s.add(nd.key); nd.children.forEach(w); }; tree.forEach(w); expanded = s; }
  function collapseAll() { expanded = new Set(); }
  function keyNav(e: KeyboardEvent, key: string, hasKids: boolean) {
    if (e.key === 'ArrowRight' && hasKids && !expanded.has(key)) { e.preventDefault(); toggle(key); }
    else if (e.key === 'ArrowLeft' && expanded.has(key)) { e.preventDefault(); toggle(key); }
    else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const rs = [...document.querySelectorAll<HTMLElement>('tr[data-tree]')];
      const i = rs.findIndex((r) => r === (e.currentTarget as HTMLElement));
      rs[i + (e.key === 'ArrowDown' ? 1 : -1)]?.focus();
    }
  }
  const hostIds = $derived(Object.fromEntries((res.data?.hosts ?? []).map((h: any) => [h.display_name, h.host_id])));
  const p = $derived(det.data?.params ?? {});
  const unresolved = $derived(res.data?.unresolved_hashed_total ?? 0);
  const scanned = $derived((res.data?.hosts ?? []).filter((h: any) => !NOT_SCANNED.includes(h.status)).length);
</script>

<PageHead title="Crawl tree · scan #{sid}">
  {#snippet sub()}
    depth ≤{p.max_depth ?? '–'} · max hosts {n(p.max_hosts)} · {#if unresolved > 0}<a href="/s/{sid}/hosts?sort=unresolved_hashed">{n(unresolved)} hashed known_hosts {unresolved === 1 ? 'entry' : 'entries'} could not be matched to any host.</a>{:else}every hashed known_hosts entry was matched{/if}
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
  <div class="filters">
    <label class="row meta secondary">Status
      <select class="select" bind:value={statusFilter}>
        <option value="all">all</option><option value="ok">ok</option><option value="partial">partial</option>
        <option value="unreachable">unreachable</option><option value="hostkey_mismatch">host key changed</option><option value="not_scanned">not scanned</option>
      </select>
    </label>
    <label class="check"><input type="checkbox" bind:checked={showRefs} />Show not-scanned references</label>
    <button class="btn ghost" onclick={expandAll}>Expand all</button>
    <button class="btn ghost" onclick={collapseAll}>Collapse all</button>
  </div>
  <section class="panel flush">
    <div class="table-wrap">
      <table class="t tree" role="treegrid" aria-label="Crawl tree">
        <thead><tr><th>Host</th><th class="r">Depth</th><th>Status</th><th>Privilege</th><th>Route</th><th>Discovered via</th></tr></thead>
        <tbody>
          {#each rows.slice(0, MAXROWS) as { nd, hasKids } (nd.key)}
            {#if nd.kind === 'host'}
              {@const h = nd.h}
              {@const failed = (h.route_attempts ?? []).filter((a: any) => a.error)}
              <tr data-tree tabindex="0" aria-level={nd.depth + 1} aria-expanded={hasKids ? expanded.has(nd.key) : undefined}
                onkeydown={(e) => keyNav(e, nd.key, hasKids)} class:ns={NOT_SCANNED.includes(h.status)}>
                <td class="hcell">
                  <span class="ind" style:width="{nd.depth * 16}px" aria-hidden="true"></span>
                  {#if hasKids}<button class="tw" aria-label={expanded.has(nd.key) ? 'Collapse' : 'Expand'} onclick={() => toggle(nd.key)}>{expanded.has(nd.key) ? '▾' : '▸'}</button>{:else}<span class="tw"></span>{/if}
                  {#if NOT_SCANNED.includes(h.status)}<span class="mono muted">{h.display_name}</span>{:else}<a class="mono" href={hostHref(sid, h.host_id)}>{h.display_name}</a>{/if}
                </td>
                <td class="r num">{h.depth ?? '–'}</td>
                <td>{#if NOT_SCANNED.includes(h.status)}<span class="chip ref">{OUTCOME_CHIP[h.status] ?? STATUS_LABEL[h.status] ?? h.status}</span>{:else}<StatusBadge status={h.status} />{/if}</td>
                <td>{NOT_SCANNED.includes(h.status) ? '–' : privilege(h.privilege)}</td>
                <td>
                  {#if NOT_SCANNED.includes(h.status)}<span class="muted">– seen only</span>{:else}<HopChain route={h.route} links={hostIds} scan={sid} />{/if}
                  {#if failed.length && h.status !== 'unreachable'}
                    <button class="btn ghost small" onclick={() => { const s = new Set(attemptsOpen); s.has(h.host_id) ? s.delete(h.host_id) : s.add(h.host_id); attemptsOpen = s; }}>↺ {failed.length} failed attempt{failed.length > 1 ? 's' : ''}</button>
                  {:else if h.status === 'unreachable' || h.status === 'timeout'}
                    <button class="btn ghost small" onclick={() => { const s = new Set(attemptsOpen); s.has(h.host_id) ? s.delete(h.host_id) : s.add(h.host_id); attemptsOpen = s; }}>↺ {failed.length} failed attempt{failed.length !== 1 ? 's' : ''}</button>
                  {/if}
                  {#if attemptsOpen.has(h.host_id)}
                    <ul class="att mono">{#each h.route_attempts as a}<li>{(a.route ?? []).join(' → ')}: <span class={a.error ? 'err' : 'okk'}>{a.error ?? 'ok'}</span></li>{/each}</ul>
                  {/if}
                </td>
                <td class="mono via" title={fileLine(h.via?.file, h.via?.line)}>
                  {#if h.via?.parent}{fileLine(h.via.file, h.via.line)}{#if h.via.source === 'known_hosts_hashed'} <span class="secondary">(hashed)</span>{/if}{:else}<span class="secondary">{h.via?.source === 'entry' ? 'entry' : h.via?.source ?? '–'}</span>{/if}
                </td>
              </tr>
            {:else}
              {@const r = nd.r}
              <tr data-tree tabindex="0" aria-level={nd.depth + 1} onkeydown={(e) => keyNav(e, nd.key, false)} class="ns">
                <td class="hcell"><span class="ind" style:width="{nd.depth * 16}px" aria-hidden="true"></span><span class="tw"></span><span class="mono muted">{r.value}</span></td>
                <td></td>
                <td><span class="chip ref">{r.outcome === 'alias' ? `Alias of ${r.target ?? '?'}` : OUTCOME_CHIP[r.outcome] ?? r.outcome}</span></td>
                <td></td>
                <td class="muted">{SOURCE_LABEL[r.source] ?? r.source}{#if r.username}{' · '}{r.username}{/if}</td>
                <td class="mono via muted" title={fileLine(r.file, r.line)}>{fileLine(r.file, r.line)}</td>
              </tr>
            {/if}
          {/each}
          {#if rows.length > MAXROWS}<tr><td colspan="6" class="meta secondary">Showing the first {n(MAXROWS)} of {n(rows.length)} rows. Collapse branches or filter by status to see the rest.</td></tr>{/if}
        </tbody>
      </table>
    </div>
  </section>
{/if}

<style>
  .hcell { white-space: nowrap; }
  .ind { display: inline-block; height: 1px; vertical-align: middle; border-bottom: 1px solid var(--border-subtle); }
  .tw { display: inline-flex; width: 24px; height: 24px; align-items: center; justify-content: center; border: 0; background: none;
    color: var(--text-secondary); cursor: pointer; vertical-align: middle; }
  .chip.ref { background: var(--info-bg); color: var(--text-secondary); }
  tr.ns td { color: var(--text-secondary); }
  .via { white-space: nowrap; }
  .att { list-style: none; margin: var(--s2) 0 0; padding: 0; font-size: 12px; line-height: 16px; }
  .err { color: var(--high); }
  .okk { color: var(--good); }
  tr[data-tree]:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
</style>
