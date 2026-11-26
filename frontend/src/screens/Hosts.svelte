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
  import Field from '../components/Field.svelte';

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
<PageHead title="Hosts">
  {#snippet fields()}
    <Field label="Showing">{#if res.data}{n(res.data.total)} of {n(Object.values(res.data.status_counts ?? {}).reduce((a: number, v: any) => a + v, 0))}{:else}…{/if}</Field>
    <Field label="Scan">Scan #{sid} <span class="secondary">{scan.label || 'unlabelled'}</span></Field>
  {/snippet}
  {#snippet actions()}
    <div class="exp">
      <button class="btn" aria-haspopup="menu" aria-expanded={exportOpen} onclick={() => (exportOpen = !exportOpen)}>Export<svg class="chev" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M3 4.5 6 7.5 9 4.5" fill="none" stroke="currentColor" stroke-width="1.5" /></svg></button>
      {#if exportOpen}<div class="popover expmenu" role="menu">
        <a role="menuitem" href="/api/scans/{sid}/export/hosts.csv{exportQs}" download>Hosts (CSV)</a>
        <a role="menuitem" href="/api/scans/{sid}/export/hosts.json{exportQs}" download>Hosts (JSON)</a>
      </div>{/if}
    </div>
  {/snippet}
</PageHead>
<Notices {scan} partial />

<section class="panel flush">
<div class="toolbar">
  <input class="input qi" type="search" placeholder="Search name or IP" aria-label="Search name or IP" bind:value={qInput} oninput={onQ} />
  <MultiSelect label="Status" options={statusOpts} value={Q.status ? Q.status.split(',') : []} onchange={(v) => setQuery({ status: v.join(','), page: null })} />
  <MultiSelect label="Privilege" options={[{ value: 'root', label: 'root' }, { value: 'sudo_password', label: 'sudo password' }, { value: 'unprivileged', label: 'unprivileged' }, { value: 'none', label: 'not scanned' }]}
    value={Q.privilege ? Q.privilege.split(',') : []} onchange={(v) => setQuery({ privilege: v.join(','), page: null })} />
  <label class="ctl">Group by
    <select class="select" value={groupKind} onchange={(e) => setQuery({ group_kind: (e.target as HTMLSelectElement).value, group: null, page: null })}>
      <option value="subnet">Subnet</option><option value="ansible">Ansible group</option><option value="tag">Tag</option><option value="depth">Crawl depth</option>
    </select>
    <select class="select" aria-label="Group" value={Q.group} onchange={(e) => setQuery({ group_kind: groupKind, group: (e.target as HTMLSelectElement).value, page: null })}>
      <option value="">All groups</option>
      {#each groupVals as g}<option value={g}>{groupKind === 'depth' ? `Depth ${g}` : g}</option>{/each}
    </select>
  </label>
</div>
{#if filtered}
  <div class="applied">
    {#if Q.q}<button class="chip filter" onclick={() => { qInput = ''; setQuery({ q: null }); }}>Search: {Q.q} ×</button>{/if}
    {#if Q.status}<button class="chip filter" onclick={() => setQuery({ status: null })}>Status: {Q.status.split(',').map((s) => STATUS_LABEL[s] ?? s).join(', ')} ×</button>{/if}
    {#if Q.privilege}<button class="chip filter" onclick={() => setQuery({ privilege: null })}>Privilege: {Q.privilege.split(',').map(privilege).join(', ')} ×</button>{/if}
    {#if Q.group}<button class="chip filter" onclick={() => setQuery({ group: null, group_kind: null })}>{groupKind}: {Q.group} ×</button>{/if}
    <button class="btn ghost small" onclick={clear}>Clear filters</button>
  </div>
{/if}

{#if res.error}
  <div class="pad"><ErrorPanel thing="hosts" message={res.error} retry={load} /></div>
{:else if !res.data}
  {#if res.slow}<Skeleton />{/if}
{:else}
    <div class="table-wrap">
      <table class="t hosts">
        <thead><tr>
          <SortTh label="Host" key="name" sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />
          <th>IPs</th><th>Status</th><th>Privilege</th>
          <SortTh label="Depth" key="depth" right sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />
          <th>Group</th>
          <SortTh label="In" key="in_hosts" right defaultDesc sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />
          <SortTh label="Out" key="out_hosts" right defaultDesc sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />
          <SortTh label="Unknown" key="in_unknown_keys" right defaultDesc sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />
          <SortTh label="Findings" key="findings" defaultDesc sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />
          {#if Q.sort === 'unresolved_hashed'}<SortTh label="Unmatched hashed" key="unresolved_hashed" right defaultDesc sort={Q.sort} order={Q.order} onsort={(k, o) => setQuery({ sort: k, order: o === 'default' ? null : o })} />{/if}
        </tr></thead>
        <tbody>
          {#each res.data.items as h (h.host_id)}
            <tr>
              <td class="ent"><a href={hostHref(sid, h.host_id)} title={h.display_name}>{endTrunc(h.display_name, 34)}</a></td>
              <td class="num" title={h.ips.join(', ')}>{h.ips[0] ?? '–'}{#if h.ips.length > 1}<span class="muted">{' +'}{h.ips.length - 1}</span>{/if}</td>
              <td><StatusBadge status={h.status} /></td>
              <td>{privilege(h.privilege)}</td>
              <td class="r num">{h.depth ?? '–'}</td>
              <td>{groupLabel(h)}</td>
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
  <Pagination total={res.data.total} page={Q.page} pageSize={Q.page_size} onchange={(p, s) => setQuery({ page: p > 1 ? p : null, size: s !== 100 ? s : null })} />
{/if}
</section>

<style>
  .qi { width: 220px; }
  .pad { padding: var(--s5); }
  .fs { display: inline-flex; gap: var(--s3); }
  .chev { color: var(--text-muted); }
</style>
