<script lang="ts">
  // Hosts (design §4.7).
  import { api, qs } from '../lib/api';
  import { route, setQuery } from '../lib/router.svelte';
  import { Resource } from '../lib/state.svelte';
  import { endTrunc, n, privilege, SEVERITIES, STATUS_LABEL } from '../lib/format';
  import { hostHref } from '../lib/links';
  import PageHead from '../components/PageHead.svelte';
  import Notices from '../components/Notices.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import SevBadge from '../components/SevBadge.svelte';
  import MultiSelect from '../components/MultiSelect.svelte';
  import SortTh from '../components/SortTh.svelte';
  import Pagination from '../components/Pagination.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import Glyph from '../components/Glyph.svelte';

  let { scan }: { scan: any } = $props();
  const sid = scan.id;
  const Q = $derived({
    q: route.query.get('q') ?? '', status: route.query.get('status') ?? '', privilege: route.query.get('privilege') ?? '',
    group_kind: route.query.get('group_kind') ?? '', group: route.query.get('group') ?? '',
    sort: route.query.get('sort') ?? 'name', order: route.query.get('order') ?? 'default',
    page: +(route.query.get('page') ?? 1), page_size: +(route.query.get('size') ?? 100),
  });
  const res = new Resource<any>();
  const params = $derived({ ...Q, page_size: Q.page_size });
  const load = () => res.load(() => api(`/scans/${sid}/hosts` + qs(params)), true);
  $effect(() => { params; load(); });

  let qInput = $state(route.query.get('q') ?? '');
  let qt: number | undefined;
  function onQ() { clearTimeout(qt); qt = window.setTimeout(() => setQuery({ q: qInput, page: null }, true), 250); }
  const filtered = $derived(!!(Q.q || Q.status || Q.privilege || Q.group));
  function clear() { qInput = ''; setQuery({ q: null, status: null, privilege: null, group_kind: null, group: null, page: null }); }
  const statusOpts = $derived(Object.entries(res.data?.status_counts ?? {}).map(([k, v]) => ({ value: k, label: STATUS_LABEL[k] ?? k, count: v as number })));
  const groupKind = $derived(Q.group_kind || 'subnet');
  const groupVals = $derived((res.data?.groups?.[groupKind] ?? []) as string[]);
  const groupLabel = (h: any) => groupKind === 'depth' ? `Depth ${h.depth ?? '–'}` : h.groups?.[groupKind] ?? '–';
  const exportQs = $derived(qs({ q: Q.q, status: Q.status, privilege: Q.privilege, group_kind: Q.group_kind, group: Q.group }));
  let exportOpen = $state(false);
</script>

<svelte:window onclick={(e) => { if (!(e.target as HTMLElement).closest('.exp')) exportOpen = false; }} />
<PageHead title="Hosts · {res.data ? n(res.data.total) : '…'}">
  {#snippet actions()}
    <div class="exp">
      <button class="btn" aria-haspopup="menu" aria-expanded={exportOpen} onclick={() => (exportOpen = !exportOpen)}>Export ▾</button>
      {#if exportOpen}<div class="popover expmenu" role="menu">
        <a role="menuitem" href="/api/scans/{sid}/export/hosts.csv{exportQs}" download>Hosts (CSV)</a>
        <a role="menuitem" href="/api/scans/{sid}/export/hosts.json{exportQs}" download>Hosts (JSON)</a>
      </div>{/if}
    </div>
  {/snippet}
</PageHead>
<Notices {scan} partial />

<div class="filters">
  <input class="input qi" type="search" placeholder="Search name or IP" aria-label="Search name or IP" bind:value={qInput} oninput={onQ} />
  <MultiSelect label="Status" options={statusOpts} value={Q.status ? Q.status.split(',') : []} onchange={(v) => setQuery({ status: v.join(','), page: null })} />
  <MultiSelect label="Privilege" options={[{ value: 'root', label: 'root' }, { value: 'sudo_password', label: 'sudo password' }, { value: 'unprivileged', label: 'unprivileged' }, { value: 'none', label: 'not scanned' }]}
    value={Q.privilege ? Q.privilege.split(',') : []} onchange={(v) => setQuery({ privilege: v.join(','), page: null })} />
  <label class="row meta secondary">Group by
    <select class="select" value={groupKind} onchange={(e) => setQuery({ group_kind: (e.target as HTMLSelectElement).value, group: null, page: null })}>
      <option value="subnet">subnet</option><option value="ansible">Ansible group</option><option value="tag">tag</option><option value="depth">crawl depth</option>
    </select>
    <select class="select" aria-label="Group" value={Q.group} onchange={(e) => setQuery({ group_kind: groupKind, group: (e.target as HTMLSelectElement).value, page: null })}>
      <option value="">= all</option>
      {#each groupVals as g}<option value={g}>{groupKind === 'depth' ? `Depth ${g}` : g}</option>{/each}
    </select>
  </label>
  {#if filtered}<button class="btn ghost" onclick={clear}>Clear filters</button>{/if}
</div>
{#if filtered}
  <div class="applied">
    {#if Q.q}<button class="chip filter" onclick={() => { qInput = ''; setQuery({ q: null }); }}>Search: {Q.q} ×</button>{/if}
    {#if Q.status}<button class="chip filter" onclick={() => setQuery({ status: null })}>Status: {Q.status.split(',').map((s) => STATUS_LABEL[s] ?? s).join(', ')} ×</button>{/if}
    {#if Q.privilege}<button class="chip filter" onclick={() => setQuery({ privilege: null })}>Privilege: {Q.privilege.split(',').map(privilege).join(', ')} ×</button>{/if}
    {#if Q.group}<button class="chip filter" onclick={() => setQuery({ group: null, group_kind: null })}>{groupKind}: {Q.group} ×</button>{/if}
  </div>
{/if}

{#if res.error}
  <ErrorPanel thing="hosts" message={res.error} retry={load} />
{:else if !res.data}
  {#if res.slow}<div class="panel flush"><Skeleton /></div>{/if}
{:else}
  <Pagination total={res.data.total} page={Q.page} pageSize={Q.page_size} onchange={(p, s) => setQuery({ page: p > 1 ? p : null, size: s !== 100 ? s : null })} />
  <section class="panel flush">
    <div class="table-wrap">
      <table class="t hosts">
        <thead><tr>
          <SortTh label="Host" key="name" sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />
          <th>IPs</th><th>Status</th><th>Privilege</th>
          <SortTh label="Depth" key="depth" right sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />
          <th>Group</th>
          <SortTh label="In" key="in_hosts" right defaultDesc sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />
          <SortTh label="Out" key="out_hosts" right defaultDesc sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />
          <SortTh label="Unk" key="in_unknown_keys" right defaultDesc sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />
          <SortTh label="Findings" key="findings" defaultDesc sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />
          {#if Q.sort === 'unresolved_hashed'}<SortTh label="Unmatched hashed" key="unresolved_hashed" right defaultDesc sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />{/if}
        </tr></thead>
        <tbody>
          {#each res.data.items as h (h.host_id)}
            <tr>
              <td class="mono"><a href={hostHref(sid, h.host_id)} title={h.display_name}>{endTrunc(h.display_name, 34)}</a>{#if h.status === 'partial'}<span class="pg sev-medium" title="Scanned partially"><Glyph kind="medium" /></span>{/if}</td>
              <td class="mono" title={h.ips.join(', ')}>{h.ips[0] ?? '–'}{#if h.ips.length > 1}<span class="muted"> +{h.ips.length - 1}</span>{/if}</td>
              <td><StatusBadge status={h.status} /></td>
              <td>{privilege(h.privilege)}</td>
              <td class="r num">{h.depth ?? '–'}</td>
              <td class="mono">{groupLabel(h)}</td>
              <td class="r num">{h.metrics.in_hosts}</td>
              <td class="r num">{h.metrics.out_hosts}</td>
              <td class="r num">{h.metrics.in_unknown_keys}</td>
              <td><span class="fs">{#each SEVERITIES as s}{#if h.findings_by_severity[s]}<SevBadge severity={s} count={h.findings_by_severity[s]} compact />{/if}{/each}</span></td>
              {#if Q.sort === 'unresolved_hashed'}<td class="r num">{h.unresolved_hashed}</td>{/if}
            </tr>
          {:else}
            <tr><td class="empty" colspan="11">
              {#if filtered}No hosts match these filters in scan #{sid}. <button class="btn small" onclick={clear}>Clear filters</button>{:else}No hosts in scan #{sid}.{/if}
            </td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
  <Pagination total={res.data.total} page={Q.page} pageSize={Q.page_size} onchange={(p, s) => setQuery({ page: p > 1 ? p : null, size: s !== 100 ? s : null })} />
{/if}

<style>
  .qi { width: 220px; }
  .fs { display: inline-flex; gap: var(--s3); }
  .pg { color: var(--c); margin-left: var(--s2); }
  .exp { position: relative; }
  .expmenu { right: 0; top: 36px; display: flex; flex-direction: column; padding: var(--s2) 0; min-width: 160px; }
  .expmenu a { padding: var(--s3) var(--s4); color: var(--text-primary); }
  .expmenu a:hover { background: var(--bg-hover); text-decoration: none; }
  .hosts td:first-child { position: sticky; left: 0; background: inherit; }
</style>
