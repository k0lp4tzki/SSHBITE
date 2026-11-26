<script lang="ts">
  // Skeleton rows: bg.sunken bars, no shimmer (design §3).
  let { rows = 12 }: { rows?: number } = $props();
  const widths = [38, 22, 14, 30, 18, 26];
</script>

<div aria-busy="true" aria-label="Loading">
  {#each Array(rows) as _, i}
    <div class="skeleton-row">
      {#each widths as w, j}<span class="skeleton-bar" style:width="{((w + i * 7 + j * 5) % 30) + 8}%"></span>{/each}
    </div>
  {/each}
</div>
