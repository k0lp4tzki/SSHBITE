<script lang="ts">
  // Route as a hop chain: "jump → b3 → c1" in Sans 13, the arrow in text.muted - here it is direction and content
  // (design-revision §4 Hop-Kette). At most 5 hops, "…" in the middle beyond.
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
  <span class="hops" title={route.join(' → ')}>
    {#each hops as h, i}
      {#if i > 0}<span class="arrow">{" → "}</span>{/if}
      {#if h !== '…' && links[h] !== undefined && scan}<a class="plain" href="/s/{scan}/hosts/{links[h]}">{h}</a>{:else}<span>{h}</span>{/if}
    {/each}
  </span>
{/if}
<style>
  .hops { font-size: 13px; line-height: 20px; white-space: nowrap; }
  .arrow { color: var(--text-muted); white-space: pre; }
</style>
