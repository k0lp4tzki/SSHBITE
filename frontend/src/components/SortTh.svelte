<script lang="ts">
  // Sortable header (design-revision §4): the sort mark only on the sorted column; aria-sort.
  let { label, key, sort, order = 'default', right = false, defaultDesc = false, onsort }:
    { label: string; key: string; sort: string; order?: string; right?: boolean; defaultDesc?: boolean; onsort: (key: string, order: string) => void } = $props();
  const active = $derived(sort === key);
  const desc = $derived(active && (order === 'desc' || (order === 'default' && defaultDesc)));
  function click() {
    if (!active) onsort(key, 'default');
    else onsort(key, desc ? 'asc' : 'desc');
  }
</script>

<th class:r={right} aria-sort={active ? (desc ? 'descending' : 'ascending') : 'none'}>
  <button class="sort" class:on={active} onclick={click}>{label}{#if active}<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d={desc ? 'M6 2.5v7M3 6.5l3 3 3-3' : 'M6 9.5v-7M3 5.5l3-3 3 3'} fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg>{/if}</button>
</th>
<style>
  .on { color: var(--text-primary); }
</style>
