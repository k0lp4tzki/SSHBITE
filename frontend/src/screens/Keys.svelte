<script lang="ts">
  // Keys (design §4.9).
  import { api, qs } from '../lib/api';
  import { route, setQuery } from '../lib/router.svelte';
  import { Resource } from '../lib/state.svelte';
  import { n, STRENGTH_LABEL } from '../lib/format';
  import { keyHref } from '../lib/links';
  import PageHead from '../components/PageHead.svelte';
  import Notices from '../components/Notices.svelte';
  import StrengthChip from '../components/StrengthChip.svelte';
  import KeyType from '../components/KeyType.svelte';
  import Fp from '../components/Fp.svelte';
  import Glyph from '../components/Glyph.svelte';
  import MultiSelect from '../components/MultiSelect.svelte';
  import SortTh from '../components/SortTh.svelte';
  import Pagination from '../components/Pagination.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';
  import Skeleton from '../components/Skeleton.svelte';

  let { scan }: { scan: any } = $props();
  const sid = scan.id;
  const Q = $derived({
    q: route.query.get('q') ?? '', strength: route.query.get('strength') ?? '', origin: route.query.get('origin') ?? '',
    sort: route.query.get('sort') ?? 'strength', order: route.query.get('order') ?? 'default',
    page: +(route.query.get('page') ?? 1), page_size: +(route.query.get('size') ?? 100),
  });
  const res = new Resource<any>();
  const load = () => res.load(() => api(`/scans/${sid}/keys` + qs(Q)), true);
  $effect(() => { Q; load(); });
  let qInput = $state(route.query.get('q') ?? '');
  let qt: number | undefined;
  function onQ() { clearTimeout(qt); qt = window.setTimeout(() => setQuery({ q: qInput, page: null }, true), 250); }
  const filtered = $derived(!!(Q.q || Q.strength || Q.origin));
  function clear() { qInput = ''; setQuery({ q: null, strength: null, origin: null, page: null }); }
  const sorter = (k: string, o: string) => setQuery({ sort: k, order: o === 'default' ? null : o });
  const exportQs = $derived(qs({ q: Q.q, strength: Q.strength, origin: Q.origin }));
  let exportOpen = $state(false);
</script>

<svelte:window onclick={(e) => { if (!(e.target as HTMLElement).closest('.exp')) exportOpen = false; }} />
<PageHead title="Keys · {res.data ? n(res.data.total) : '…'}">
  {#snippet actions()}
    <div class="exp">
      <button class="btn" aria-haspopup="menu" aria-expanded={exportOpen} onclick={() => (exportOpen = !exportOpen)}>Export ▾</button>
      {#if exportOpen}<div class="popover expmenu" role="menu">
        <a role="menuitem" href="/api/scans/{sid}/export/keys.csv{exportQs}" download>Keys (CSV)</a>
        <a role="menuitem" href="/api/scans/{sid}/export/keys.json{exportQs}" download>Keys (JSON)</a>
      </div>{/if}
    </div>
  {/snippet}
</PageHead>
<Notices {scan} />

<div class="filters">
  <input class="input qi" type="search" placeholder="Search fingerprint, comment or label" aria-label="Search fingerprint, comment or label" bind:value={qInput} oninput={onQ} />
  <MultiSelect label="Strength" options={['critical', 'weak', 'ok', 'good', 'unknown'].map((s) => ({ value: s, label: STRENGTH_LABEL[s], count: res.data?.strength_counts?.[s] ?? 0 }))}
    value={Q.strength ? Q.strength.split(',') : []} onchange={(v) => setQuery({ strength: v.join(','), page: null })} />
  <div class="seg" role="radiogroup" aria-label="Origin">
    {#each [['', 'All'], ['known', 'Known'], ['unknown', 'Unknown origin']] as [v, l]}
      <button role="radio" aria-checked={Q.origin === v} onclick={() => setQuery({ origin: v, page: null })}>{l}</button>
    {/each}
  </div>
  {#if filtered}<button class="btn ghost" onclick={clear}>Clear filters</button>{/if}
</div>
{#if filtered}
  <div class="applied">
    {#if Q.q}<button class="chip filter" onclick={() => { qInput = ''; setQuery({ q: null }); }}>Search: {Q.q} ×</button>{/if}
    {#if Q.strength}<button class="chip filter" onclick={() => setQuery({ strength: null })}>Strength: {Q.strength.split(',').map((s) => STRENGTH_LABEL[s]).join(', ')} ×</button>{/if}
    {#if Q.origin}<button class="chip filter" onclick={() => setQuery({ origin: null })}>Origin: {Q.origin} ×</button>{/if}
  </div>
{/if}

{#if res.error}
  <ErrorPanel thing="keys" message={res.error} retry={load} />
{:else if !res.data}
  {#if res.slow}<div class="panel flush"><Skeleton /></div>{/if}
{:else}
  <Pagination total={res.data.total} page={Q.page} pageSize={Q.page_size} onchange={(p, s) => setQuery({ page: p > 1 ? p : null, size: s !== 100 ? s : null })} />
  <section class="panel flush">
    <div class="table-wrap">
      <table class="t">
        <thead><tr>
          <SortTh label="Fingerprint" key="fp" sort={Q.sort} order={Q.order} onsort={sorter} />
          <th>Type</th>
          <SortTh label="Bits" key="bits" right defaultDesc sort={Q.sort} order={Q.order} onsort={sorter} />
          <SortTh label="Strength" key="strength" sort={Q.sort} order={Q.order} onsort={sorter} />
          <SortTh label="Label" key="label" sort={Q.sort} order={Q.order} onsort={sorter} />
          <th>Comments</th>
          <SortTh label="Authorized hosts" key="authorized_hosts" right defaultDesc sort={Q.sort} order={Q.order} onsort={sorter} />
          <SortTh label="Private holders" key="private_holders" right defaultDesc sort={Q.sort} order={Q.order} onsort={sorter} />
          <th>Origin</th>
        </tr></thead>
        <tbody>
          {#each res.data.items as k (k.fp)}
            <tr>
              <td><Fp fp={k.fp} href={keyHref(sid, k.fp)} /></td>
              <td><KeyType alg={k.alg} bits={k.bits} /></td>
              <td class="r num">{k.bits ?? '–'}</td>
              <td><StrengthChip strength={k.strength} /></td>
              <td>{#if k.label}<div>{k.label}</div>{:else}<span class="muted">–</span>{/if}{#if k.owner}<div class="meta secondary">{k.owner}</div>{/if}</td>
              <td class="mono" title={k.comments.join(', ')}>{k.comments[0] ?? '–'}{#if k.comments.length > 1}<span class="muted"> +{k.comments.length - 1}</span>{/if}</td>
              <td class="r num">{k.authorized_hosts}</td>
              <td class="r num">{k.private_holders}</td>
              <td class="nowrap">{#if k.origin === 'known'}Known{:else}<span class="sev-info unk"><Glyph kind="unknown" /></span> Unknown{/if}{#if k.cert_authority} <span class="kchip">CA</span>{/if}</td>
            </tr>
          {:else}
            <tr><td class="empty" colspan="9">{#if filtered}No keys match these filters in scan #{sid}. <button class="btn small" onclick={clear}>Clear filters</button>{:else}No keys were found in scan #{sid}.{/if}</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
  <Pagination total={res.data.total} page={Q.page} pageSize={Q.page_size} onchange={(p, s) => setQuery({ page: p > 1 ? p : null, size: s !== 100 ? s : null })} />
{/if}

<style>
  .qi { width: 300px; }
  .unk { color: var(--c); }
  .exp { position: relative; }
  .expmenu { right: 0; top: 36px; display: flex; flex-direction: column; padding: var(--s2) 0; min-width: 160px; }
  .expmenu a { padding: var(--s3) var(--s4); color: var(--text-primary); }
  .expmenu a:hover { background: var(--bg-hover); text-decoration: none; }
</style>
