<script lang="ts">
  // Page footer (design-revision §3.5: 44 px), only above 100 rows.
  import { n } from '../lib/format';
  let { total, page, pageSize, onchange }: { total: number; page: number; pageSize: number; onchange: (page: number, size: number) => void } = $props();
  const from = $derived(total === 0 ? 0 : (page - 1) * pageSize + 1);
  const to = $derived(Math.min(total, page * pageSize));
</script>
{#if total > 100}
  <nav class="tfoot" aria-label="Pagination">
    <span class="num">{n(from)}–{n(to)} of {n(total)}</span>
    <span class="row">
      <label class="ctl">Page size
        <select class="select sm" value={pageSize} onchange={(e) => onchange(1, Number((e.target as HTMLSelectElement).value))}>
          <option value={100}>100</option><option value={250}>250</option><option value={1000}>1000</option>
        </select>
      </label>
      <button class="btn small" disabled={page <= 1} onclick={() => onchange(page - 1, pageSize)}>Previous</button>
      <button class="btn small" disabled={to >= total} onclick={() => onchange(page + 1, pageSize)}>Next</button>
    </span>
  </nav>
{/if}
<style>
  .sm { height: 24px; font-size: 12px; }
</style>
