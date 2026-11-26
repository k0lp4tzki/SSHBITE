<script lang="ts">
  // Diff (design §4.12, design-revision §5.6): Before/After; signs without colour; changed rows as Field | Before | After.
  import { api } from '../lib/api';
  import { route, setQuery } from '../lib/router.svelte';
  import { diffPair, Resource, scans } from '../lib/state.svelte';
  import { fileLine, fmtTime, ruleTitle, STATUS_LABEL, EDGE_STATUS } from '../lib/format';
  import PageHead from '../components/PageHead.svelte';
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
  const T: Record<string, [string, string]> = { added: ['+', 'Added'], removed: ['−', 'Removed'], changed: ['~', 'Changed'] };
  const label = (s: any) => `#${s.id} ${s.label || 'unlabelled'}, ${fmtTime(s.started_at)}`;
  const empty = (v: any) => v === null || v === undefined || v === '' || (Array.isArray(v) && v.length === 0);
  const fmtVal = (f: string, v: any) => (f === 'route' ? (v ?? []).join(' → ') || '–' : f === 'status' ? STATUS_LABEL[v] ?? EDGE_STATUS[v] ?? v ?? '–' : v === null || v === undefined ? '–' : String(v));
  // one row per changed field: a value that went away reads "removed", never a chain ending in "→ –"
  const fieldRows = (changes: any) => Object.entries(changes ?? {}).map(([f, v]: [string, any]) => ({
    field: (f.charAt(0).toUpperCase() + f.slice(1)).replace(/_/g, ' '),
    before: fmtVal(f, v.a), after: !empty(v.a) && empty(v.b) ? 'removed' : fmtVal(f, v.b), removed: !empty(v.a) && empty(v.b),
  }));
</script>

{#snippet changeTable(changes: any)}
  <table class="sub" aria-label="Changes">
    <thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead>
    <tbody>{#each fieldRows(changes) as r}<tr><td class="secondary">{r.field}</td><td>{r.before}</td><td class:muted={r.removed}>{r.after}</td></tr>{/each}</tbody>
  </table>
{/snippet}

<PageHead title="Compare scans">
  {#snippet fields()}
    <div class="sel"><dt><label for="diff-a">Before</label></dt><dd><select id="diff-a" class="select" value={a} onchange={(e) => setQuery({ a: (e.target as HTMLSelectElement).value })}>
      {#each scans.items as s}<option value={s.id}>{label(s)}</option>{/each}</select></dd></div>
    <div class="sel"><dt><label for="diff-b">After</label></dt><dd><select id="diff-b" class="select" value={b} onchange={(e) => setQuery({ b: (e.target as HTMLSelectElement).value })}>
      {#each scans.items as s}<option value={s.id}>{label(s)}</option>{/each}</select></dd></div>
  {/snippet}
  {#snippet actions()}
    {#if a && b && a !== b}<a class="btn" href="/api/diff?a={a}&b={b}&download=1" download>Export JSON</a>{/if}
  {/snippet}
</PageHead>

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
        <span>{l}{' '}<span class="cnt">{[c.a ? `+${c.a}` : '', c.r ? `−${c.r}` : '', c.c ? `~${c.c}` : ''].filter(Boolean).join(' ') || '0'}</span></span>
      </button>
    {/each}
  </div>
  <section class="panel flush">
    <div class="toolbar">
      <span class="ctl">Show</span>
      {#each ['added', 'removed', 'changed'] as k}
        <label class="check"><input type="checkbox" bind:checked={show[k as 'added']} /><span><span class="sign">{T[k][0]}</span> {T[k][1]}</span></label>
      {/each}
    </div>
    <div class="table-wrap"><table class="t">
      <thead><tr><th class="ct">Change</th><th>Item</th><th>Detail</th></tr></thead>
      <tbody>
        {#each rows as { t, x }}
          <tr class:chrow={t === 'changed'}>
            <td class="ct"><span class="chg"><span class="sign">{T[t][0]}</span> {T[t][1]}</span></td>
            {#if tab === 'hosts'}
              <td class="ent">{x.host}</td>
              <td>{#if t === 'changed'}{@render changeTable(x.changes)}{:else}<span class="det">{STATUS_LABEL[x.status] ?? x.status}{#if x.privilege}<span class="secondary">{x.privilege}</span>{/if}</span>{/if}</td>
            {:else if tab === 'keys'}
              <td><Fp fp={x.fp} /></td>
              <td><span class="det"><KeyType alg={x.alg} bits={x.bits} /><StrengthChip strength={x.strength} /><span>{x.label || x.comment || ''}</span></span></td>
            {:else if tab === 'placements'}
              <td class="nowrap"><span class="ent">{x.host}</span><span class="muted">:</span>{x.user} <span class="secondary">({x.kind === 'private' ? 'private key' : 'authorized'})</span></td>
              <td><span class="det"><Fp fp={x.fp} /><span class="mono path">{fileLine(x.file, x.line)}</span></span></td>
            {:else if tab === 'edges'}
              <td class="nowrap"><span class="ent">{x.src === 'unknown' ? 'unknown' : `${x.src}:${x.src_user ?? ''}`}</span><span class="muted">{' → '}</span>{x.dst}{x.dst_user ? ':' + x.dst_user : ''}</td>
              <td><span class="det">{#if x.fp}<Fp fp={x.fp} />{/if}<span class="kchip">{x.kind}</span>{#if t !== 'changed'}<span class="secondary">{EDGE_STATUS[x.status] ?? x.status}</span>{/if}</span>
                {#if t === 'changed'}{@render changeTable(x.changes)}{/if}</td>
            {:else}
              <td><span class="det"><SevBadge severity={x.severity} />{ruleTitle(x.rule)}</span></td>
              <td><span class="det"><span>{x.host ?? 'all hosts'}</span>{#if x.user}<span class="secondary">{x.user}</span>{/if}<span class="mono path">{fileLine(x.file, x.line)}</span></span>
                {#if t === 'changed'}{@render changeTable(x.changes)}{/if}</td>
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
  .sel dt { font-size: 12px; line-height: 16px; color: var(--text-muted); }
  .sel dd { margin: var(--s1) 0 0; }
  .sel .select { max-width: 360px; }
  .ct { width: 128px; }
  .chg { color: var(--text-primary); white-space: nowrap; }
  .sign { font-weight: 600; display: inline-block; width: .8em; text-align: center; }
  .chrow td { vertical-align: top; }
  .det { display: inline-flex; gap: var(--s3); align-items: center; flex-wrap: wrap; }
  .path { font-size: 12px; color: var(--text-secondary); }
  .sub { border-collapse: collapse; margin: var(--s1) 0; font-size: 13px; line-height: 20px; min-width: 420px; }
  .sub th { text-align: left; font-size: 12px; line-height: 16px; font-weight: 500; color: var(--text-secondary); padding: var(--s1) var(--s6) var(--s1) 0;
    border-bottom: 1px solid var(--border-subtle); }
  .sub td { padding: var(--s1) var(--s6) var(--s1) 0; border-bottom: 1px solid var(--border-subtle); vertical-align: top; }
  .sub tr:last-child td { border-bottom: 0; }
  .sub th, .sub th:first-child, .sub th:last-child { position: static; background: transparent; height: auto; padding-left: 0; }
  .sub td, .sub td:first-child, .sub td:last-child { height: auto; padding-left: 0; }
  .sub tbody tr:hover { background: transparent; }
  .det + .sub { margin-top: var(--s3); }
</style>
