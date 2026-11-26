<script lang="ts">
  // Level meter (design-revision §3.2): four bars, 2 px wide, 1 px apart, 3/6/9/12 px high, bottom aligned.
  // Filled in currentColor, empty at 25 % - the number of filled bars carries the meaning without colour.
  let { level }: { level: number } = $props();
</script>
<svg class="glyph meter" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true" focusable="false" data-level={level}>
  {#each [0, 1, 2, 3] as i}
    <rect x={i * 3 + 0.5} y={12 - (i + 1) * 3} width="2" height={(i + 1) * 3} fill="currentColor" fill-opacity={i < level ? 1 : 0.25} />
  {/each}
</svg>
