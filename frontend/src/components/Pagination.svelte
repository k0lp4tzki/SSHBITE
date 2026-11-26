<script lang="ts">
  import { n } from '../lib/format';
  let { total, page, pageSize, onchange }: { total: number; page: number; pageSize: number; onchange: (page: number, size: number) => void } = $props();
  const from = $derived(total === 0 ? 0 : (page - 1) * pageSize + 1);
  const to = $derived(Math.min(total, page * pageSize));
</script>

{#if total > 100}
  <nav class="pg" aria-label="Pagination">
    <span class="meta secondary num">{n(from)}–{n(to)} of {n(total)}</span>
    <button class="btn ghost small" disabled={page <= 1} onclick={() => onchange(page - 1, pageSize)}>‹ Prev</button>
    <button class="btn ghost small" disabled={to >= total} onclick={() => onchange(page + 1, pageSize)}>Next ›</button>
    <label class="meta secondary">Page size
      <select class="select" value={pageSize} onchange={(e) => onchange(1, Number((e.target as HTMLSelectElement).value))}>
        <option value={100}>100</option><option value={250}>250</option><option value={1000}>1000</option>
      </select>
    </label>
  </nav>
{/if}

<style>
  .pg { display: flex; align-items: center; justify-content: flex-end; gap: var(--s3); padding: var(--s3) 0; flex-wrap: wrap; }
  label { display: inline-flex; gap: var(--s3); align-items: center; }
  .select { height: 24px; font-size: 12px; }
</style>
