<script lang="ts">
  // Diff (design §4.12): pick A and B; tabs per category with added / removed / changed.
  import { api } from '../lib/api';
  import { route, setQuery } from '../lib/router.svelte';
  import { diffPair, Resource, scans } from '../lib/state.svelte';
  import { fileLine, fmtTime, ruleTitle, STATUS_LABEL, EDGE_STATUS } from '../lib/format';
  import PageHead from '../components/PageHead.svelte';
  import Glyph from '../components/Glyph.svelte';
  import Fp from '../components/Fp.svelte';
  import KeyType from '../components/KeyType.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import StrengthChip from '../components/StrengthChip.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';
  import Skeleton from '../components/Skeleton.svelte';

  const pair = $derived(diffPair(route.query));
  const a = $derived(pair[0]);
  const b = $derived(pair[1]);
  const tab = $derived(route.query.get('tab') ?? 'hosts');
  const res = new Resource<any>();
  const load = () => res.load(() => api(`/diff?a=${a}&b=${b}`));
  $effect(() => { if (a && b && a !== b) load(); });
  let show = $state({ added: true, removed: true, changed: true });

  const CATS = [['hosts', 'Hosts'], ['keys', 'Keys'], ['placements', 'Placements'], ['edges', 'Edges'], ['findings', 'Findings']];
  const counts = (c: any) => ({ a: c.added.length, r: c.removed.length, c: c.changed.length });
  const rows = $derived.by(() => {
    if (!res.data) return [];
    const c = res.data[tab];
    return [
      ...(show.added ? c.added.map((x: any) => ({ t: 'added', x })) : []),
      ...(show.removed ? c.removed.map((x: any) => ({ t: 'removed', x })) : []),
      ...(show.changed ? c.changed.map((x: any) => ({ t: 'changed', x })) : []),
    ];
  });
  const identical = $derived(res.data && CATS.every(([k]) => { const c = counts(res.data[k]); return c.a + c.r + c.c === 0; }));
  const T: Record<string, [string, string, string]> = { added: ['+ Added', 'sev-good', 'added'], removed: ['− Removed', 'sev-low', 'removed'], changed: ['~ Changed', 'sev-medium', 'changed'] };
  const label = (s: any) => `Scan #${s.id} · ${s.label || 'unlabelled'} · ${fmtTime(s.started_at)}`;
  const empty = (v: any) => v === null || v === undefined || v === '' || (Array.isArray(v) && v.length === 0);
  // "route removed (was jump → b3 → c1 → c2)" instead of a chain ending in "→ –" (a value that went away)
  const change = (f: string, v: any): [string, string] =>
    !empty(v.a) && empty(v.b) ? [`${f} removed`, `(was ${fmtVal(f, v.a)})`] : [`${f}:`, `${fmtVal(f, v.a)} → ${fmtVal(f, v.b)}`];
  const fmtVal = (f: string, v: any) => (f === 'route' ? (v ?? []).join(' → ') || '–' : f === 'status' ? STATUS_LABEL[v] ?? EDGE_STATUS[v] ?? v ?? '–' : v === null || v === undefined ? '–' : String(v));
</script>

<PageHead title="Compare scans">
  {#snippet actions()}
    {#if a && b && a !== b}<a class="btn" href="/api/diff?a={a}&b={b}&download=1" download>Export JSON</a>{/if}
  {/snippet}
</PageHead>

<div class="filters">
  <label class="row">A <select class="select" value={a} onchange={(e) => setQuery({ a: (e.target as HTMLSelectElement).value })}>
    {#each scans.items as s}<option value={s.id}>{label(s)}</option>{/each}</select></label>
  <span class="muted" aria-hidden="true">→</span>
  <label class="row">B <select class="select" value={b} onchange={(e) => setQuery({ b: (e.target as HTMLSelectElement).value })}>
    {#each scans.items as s}<option value={s.id}>{label(s)}</option>{/each}</select></label>
</div>

{#if !a || !b}
  <p class="empty-state secondary">Two completed scans are needed for a comparison.</p>
{:else if a === b}
  <p class="empty-state secondary">Pick two different scans.</p>
{:else if res.error}
  <ErrorPanel thing="the comparison" message={res.error} retry={load} />
{:else if !res.data}
  {#if res.slow}<Skeleton />{/if}
{:else}
  {#if identical}<p class="dense secondary">Scans #{a} and #{b} are identical.</p>{/if}
  <div class="tabs" role="tablist">
    {#each CATS as [k, l]}
      {@const c = counts(res.data[k])}
      <button role="tab" aria-selected={tab === k} class:muted-tab={c.a + c.r + c.c === 0} onclick={() => setQuery({ tab: k === 'hosts' ? null : k }, true)}>
        {l} <span class="num meta">{#if c.a}+{c.a} {/if}{#if c.r}−{c.r} {/if}{#if c.c}~{c.c}{/if}{#if c.a + c.r + c.c === 0}0{/if}</span>
      </button>
    {/each}
  </div>
  <div class="row">
    {#each ['added', 'removed', 'changed'] as k}
      <label class="check {T[k][1]}"><input type="checkbox" bind:checked={show[k as 'added']} /><span class="g"><Glyph kind={T[k][2]} /></span>{T[k][0].slice(2)}</label>
    {/each}
  </div>
  <section class="panel flush">
    <div class="table-wrap"><table class="t">
      <thead><tr><th class="ct">Change</th><th>Item</th><th>Detail</th></tr></thead>
      <tbody>
        {#each rows as { t, x }}
          <tr>
            <td class="ct"><span class="chg {T[t][1]}"><Glyph kind={T[t][2]} />{T[t][0].slice(2)}</span></td>
            {#if tab === 'hosts'}
              <td class="mono">{x.host}</td>
              <td>{#if t === 'changed'}{#each Object.entries(x.changes) as [f, v]}{@const c = change(f, v)}<div class="dense"><span class="secondary">{c[0]}</span> <span class="mono">{c[1]}</span></div>{/each}{:else}{STATUS_LABEL[x.status] ?? x.status}{#if x.privilege}{' · '}{x.privilege}{/if}{/if}</td>
            {:else if tab === 'keys'}
              <td><Fp fp={x.fp} /></td>
              <td><span class="row nowrap"><KeyType alg={x.alg} bits={x.bits} /><StrengthChip strength={x.strength} /><span class="mono">{x.label || x.comment || ''}</span></span></td>
            {:else if tab === 'placements'}
              <td class="mono">{x.host}:{x.user} <span class="secondary sans">({x.kind === 'private' ? 'private key' : 'authorized'})</span></td>
              <td><span class="row nowrap"><Fp fp={x.fp} /><span class="mono meta secondary">{fileLine(x.file, x.line)}</span></span></td>
            {:else if tab === 'edges'}
              <td class="mono">{x.src === 'unknown' ? 'unknown' : `${x.src}:${x.src_user ?? ''}`} → {x.dst}{x.dst_user ? ':' + x.dst_user : ''}</td>
              <td><span class="row nowrap">{#if x.fp}<Fp fp={x.fp} />{/if}<span class="kchip">{x.kind}</span>
                {#if t === 'changed'}{#each Object.entries(x.changes) as [f, v]}{@const c = change(f, v)}<span class="mono dense">{c[0]} {c[1]}</span>{/each}{:else}<span class="secondary">{EDGE_STATUS[x.status] ?? x.status}</span>{/if}</span></td>
            {:else}
              <td><span class="row nowrap"><SevBadge severity={x.severity} />{ruleTitle(x.rule)}</span></td>
              <td class="mono dense">{[x.host, x.user].filter(Boolean).join(' · ') || 'all hosts'} {fileLine(x.file, x.line)}{#if t === 'changed'}{' · '}severity {x.changes.severity?.a} → {x.changes.severity?.b}{/if}</td>
            {/if}
          </tr>
        {:else}
          <tr><td class="empty" colspan="3">No {tab} changed between scan #{a} and #{b}.</td></tr>
        {/each}
      </tbody>
    </table></div>
  </section>
{/if}

<style>
  .ct { width: 120px; }
  .chg { display: inline-flex; gap: var(--s2); align-items: center; color: var(--c); font-weight: 500; }
  .g { color: var(--c); display: inline-flex; }
  .select { max-width: 420px; }
  .sans { font-family: var(--sans); }
</style>
