<script lang="ts">
  // Route as a hop chain: "jump → b3 → c1" (design §1, §6.2); at most 5 hops, "…" in the middle beyond.
  let { route, links = {}, scan = 0 }: { route: string[] | null | undefined; links?: Record<string, number>; scan?: number } = $props();
  const hops = $derived.by(() => {
    const r = route ?? [];
    if (r.length <= 5) return r;
    return [r[0], r[1], '…', r[r.length - 2], r[r.length - 1]];
  });
</script>

{#if !route || route.length === 0}
  <span class="muted">–</span>
{:else}
  <span class="hops mono" title={route.join(' → ')}>
    {#each hops as h, i}
      {#if i > 0}<span class="arrow">{" → "}</span>{/if}
      {#if h !== '…' && links[h] !== undefined && scan}<a href="/s/{scan}/hosts/{links[h]}">{h}</a>{:else}<span>{h}</span>{/if}
    {/each}
  </span>
{/if}

<style>
  .hops { font-size: 13px; line-height: 18px; white-space: nowrap; }
  .arrow { color: var(--text-muted); }
</style>
