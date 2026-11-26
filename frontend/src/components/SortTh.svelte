<script lang="ts">
  // Sortable header: ▲/▼ and aria-sort (design §6.2).
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
  <button class="sort" onclick={click}>{label}{#if active}<span aria-hidden="true">{desc ? '▼' : '▲'}</span>{/if}</button>
</th>
