<script lang="ts">
  import Meter from './Meter.svelte';
  let { thing, message, retry }: { thing: string; message: string; retry?: () => void } = $props();
</script>
<div class="strip error" role="alert">
  <span class="gl"><Meter level={4} /></span>
  <div class="body">Couldn't load {thing}: {message}</div>
  {#if retry}<button class="btn small" onclick={retry}>Try again</button>{/if}
</div>
<style>
  .body { flex: 1; }
  .strip { align-items: center; }
  .strip .gl { padding-top: 0; }
</style>
