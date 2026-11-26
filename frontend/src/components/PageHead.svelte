<script lang="ts">
  // Page header (design-revision §4 Seitenkopf): title in type.title, an optional badge beside it, the context
  // fields below (label above value), actions on the title line - at most one primary.
  import type { Snippet } from 'svelte';
  let { title, badge = undefined, actions = undefined, fields = undefined, sub = undefined }:
    { title: string; badge?: Snippet; actions?: Snippet; fields?: Snippet; sub?: Snippet } = $props();
</script>
<header class="ph">
  <div class="tl">
    <div class="trow"><h1 class="page-title">{title}</h1>{#if badge}{@render badge()}{/if}</div>
    {#if sub}<div class="sub">{@render sub()}</div>{/if}
    {#if fields}<dl class="ctx">{@render fields()}</dl>{/if}
  </div>
  {#if actions}<div class="act">{@render actions()}</div>{/if}
</header>
<style>
  .ph { margin-bottom: var(--s2); display: flex; justify-content: space-between; align-items: flex-start; gap: var(--s5); flex-wrap: wrap; }
  .tl { min-width: 0; display: flex; flex-direction: column; gap: var(--s2); flex: 1 1 auto; }
  .trow { display: flex; align-items: center; gap: var(--s3); flex-wrap: wrap; min-height: 32px; }
  .sub { color: var(--text-secondary); font-size: 13px; line-height: 20px; }
  .tl :global(.ctx) { margin-top: var(--s2); }
  .act { display: flex; gap: var(--s3); align-items: center; flex-wrap: wrap; }
  h1 { overflow-wrap: anywhere; }
</style>
