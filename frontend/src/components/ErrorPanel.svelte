<script lang="ts">
  import Glyph from './Glyph.svelte';
  let { thing, message, retry }: { thing: string; message: string; retry?: () => void } = $props();
</script>

<div class="strip error" role="alert">
  <span class="sev-critical"><span class="gl"><Glyph kind="critical" /></span></span>
  <div class="body">Couldn't load {thing}: {message}</div>
  {#if retry}<button class="btn small" onclick={retry}>Try again</button>{/if}
</div>

<style>
  .gl { color: var(--c); display: inline-flex; padding-top: 4px; }
  .body { flex: 1; }
  .strip { align-items: center; }
</style>
