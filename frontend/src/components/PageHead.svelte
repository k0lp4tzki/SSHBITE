<script lang="ts">
  import type { Snippet } from 'svelte';
  let { title, mono = false, actions = undefined, sub = undefined }: { title: string; mono?: boolean; actions?: Snippet; sub?: Snippet } = $props();
</script>

<header class="ph">
  <div class="tl">
    <h1 class="page-title" class:mono>{title}</h1>
    {#if sub}<div class="sub">{@render sub()}</div>{/if}
  </div>
  {#if actions}<div class="act">{@render actions()}</div>{/if}
</header>

<style>
  .ph { display: flex; justify-content: space-between; align-items: flex-start; gap: var(--s5); flex-wrap: wrap; }
  .tl { min-width: 0; display: flex; flex-direction: column; gap: var(--s2); }
  .sub { color: var(--text-secondary); font-size: 13px; line-height: 18px; }
  .act { display: flex; gap: var(--s3); align-items: center; flex-wrap: wrap; }
  h1 { overflow-wrap: anywhere; }
</style>
