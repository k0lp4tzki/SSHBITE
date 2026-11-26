<script lang="ts">
  // Findings (design-revision §5.5): page header with Showing, Export CSV primary; toolbar in the panel.
  import { api, qs } from '../lib/api';
  import { route, setQuery } from '../lib/router.svelte';
  import { Resource } from '../lib/state.svelte';
  import { n, RULES, ruleTitle, SEV_LABEL } from '../lib/format';
  import PageHead from '../components/PageHead.svelte';
  import Field from '../components/Field.svelte';
  import Notices from '../components/Notices.svelte';
  import FindingsTable from '../components/FindingsTable.svelte';
  import MultiSelect from '../components/MultiSelect.svelte';
  import Combobox from '../components/Combobox.svelte';
  import Pagination from '../components/Pagination.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';
  import Skeleton from '../components/Skeleton.svelte';

  let { scan }: { scan: any } = $props();
  const sid = scan.id;
  const Q = $derived({
    severity_min: route.query.get('min') ?? route.query.get('severity_min') ?? route.query.get('severity') ?? '', severity: route.query.get('sev') ?? '', rule: route.query.get('rule') ?? '',
    host_id: route.query.get('host') ?? '', fp: route.query.get('key') ?? '', q: route.query.get('q') ?? '',
    sort: route.query.get('sort') ?? 'severity', page: +(route.query.get('page') ?? 1), page_size: +(route.query.get('size') ?? 100),
  });
  const hostName = $derived(route.query.get('hostname') ?? Q.host_id);
  const res = new Resource<any>();
  const load = () => res.load(() => api(`/scans/${sid}/findings` + qs(Q)), true);
  $effect(() => { Q; load(); });
  let qInput = $state(route.query.get('q') ?? '');
  let qt: number | undefined;
  function onQ() { clearTimeout(qt); qt = window.setTimeout(() => setQuery({ q: qInput, page: null }, true), 250); }
  const filtered = $derived(!!(Q.severity_min || Q.severity || Q.rule || Q.host_id || Q.fp || Q.q));
  function clear() { qInput = ''; setQuery({ min: null, severity: null, severity_min: null, sev: null, rule: null, host: null, hostname: null, key: null, q: null, page: null }); }
  const allCount = $derived(Object.values(res.data?.severity_counts ?? {}).reduce((a: number, v: any) => a + v, 0));
  const exportQs = $derived(qs({ severity_min: Q.severity_min, severity: Q.severity, rule: Q.rule, host_id: Q.host_id, fp: Q.fp, q: Q.q }));
  const ruleOpts = $derived(Object.keys(RULES).map((r) => ({ value: r, label: ruleTitle(r), count: res.data?.rule_counts?.[r] ?? 0 })));
</script>

<PageHead title="Findings">
  {#snippet fields()}
    <Field label="Showing">{#if res.data}{n(res.data.total)} of {n(allCount)}{:else}…{/if}</Field>
  {/snippet}
  {#snippet actions()}
    <a class="btn primary" href="/api/scans/{sid}/export/findings.csv{exportQs}" download>Export CSV ({res.data ? n(res.data.total) : '…'})</a>
    <a class="btn" href="/api/scans/{sid}/export/findings.json{exportQs}" download>Export JSON</a>
  {/snippet}
</PageHead>
<Notices {scan} />

<section class="panel flush">
  <div class="toolbar">
    <select class="select" aria-label="Severity" value={Q.severity_min} onchange={(e) => setQuery({ min: (e.target as HTMLSelectElement).value, severity: null, severity_min: null, sev: null, page: null })}>
        <option value="">All severities</option><option value="critical">Critical only</option><option value="high">High and above</option>
        <option value="medium">Medium and above</option><option value="low">Low and above</option>
      </select>
    <MultiSelect label="Rule" options={ruleOpts} value={Q.rule ? Q.rule.split(',') : []} onchange={(v) => setQuery({ rule: v.join(','), page: null })} />
    <Combobox label="Host" kind="hosts" scan={sid} onpick={(v, t) => setQuery({ host: v, hostname: t, page: null })} />
    <Combobox label="Key" kind="keys" scan={sid} onpick={(v) => setQuery({ key: v, page: null })} />
    <input class="input qi" type="search" placeholder="Search location, detail, recommendation" aria-label="Search location, detail, recommendation" bind:value={qInput} oninput={onQ} />
    <span class="spacer"></span>
    <select class="select" aria-label="Sort" value={Q.sort} onchange={(e) => setQuery({ sort: (e.target as HTMLSelectElement).value === 'severity' ? null : (e.target as HTMLSelectElement).value })}>
        <option value="severity">Sort by severity</option><option value="rule">Sort by rule</option><option value="host">Sort by host</option>
      </select>
  </div>
  {#if filtered}
    <div class="applied">
      {#if Q.severity_min}<button class="chip filter" onclick={() => setQuery({ min: null, severity: null, severity_min: null })}>Severity: {SEV_LABEL[Q.severity_min]}{Q.severity_min !== 'critical' ? ' and above' : ' only'}<span class="x" aria-hidden="true">×</span></button>{/if}
      {#if Q.severity}<button class="chip filter" onclick={() => setQuery({ sev: null })}>Severity: {Q.severity.split(',').map((s) => SEV_LABEL[s]).join(', ')}<span class="x" aria-hidden="true">×</span></button>{/if}
      {#if Q.rule}<button class="chip filter" onclick={() => setQuery({ rule: null })}>Rule: {Q.rule.split(',').map((r) => ruleTitle(r)).join(', ')}<span class="x" aria-hidden="true">×</span></button>{/if}
      {#if Q.host_id}<button class="chip filter" onclick={() => setQuery({ host: null, hostname: null })}>Host: {hostName}<span class="x" aria-hidden="true">×</span></button>{/if}
      {#if Q.fp}<button class="chip filter" onclick={() => setQuery({ key: null })}>Key: {Q.fp.slice(0, 15)}…<span class="x" aria-hidden="true">×</span></button>{/if}
      {#if Q.q}<button class="chip filter" onclick={() => { qInput = ''; setQuery({ q: null }); }}>Search: {Q.q}<span class="x" aria-hidden="true">×</span></button>{/if}
      <button class="btn ghost small" onclick={clear}>Clear filters</button>
    </div>
  {/if}

  {#if res.error}
    <div class="pad"><ErrorPanel thing="findings" message={res.error} retry={load} /></div>
  {:else if !res.data}
    {#if res.slow}<Skeleton />{/if}
  {:else}
    <FindingsTable items={res.data.items} scan={sid} empty={filtered ? `No findings of this kind in scan #${sid}.` : `No findings in scan #${sid}.`}>
      {#if filtered}<button class="btn small" onclick={clear}>Clear filters</button>{/if}
    </FindingsTable>
    <Pagination total={res.data.total} page={Q.page} pageSize={Q.page_size} onchange={(p, s) => setQuery({ page: p > 1 ? p : null, size: s !== 100 ? s : null })} />
  {/if}
</section>

<style>
  .qi { width: 220px; }
  .toolbar :global(.cb .input) { width: 128px; }
  .pad { padding: var(--s5); }
</style>
