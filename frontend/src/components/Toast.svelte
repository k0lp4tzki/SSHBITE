<script lang="ts">
  import { toast } from '../lib/state.svelte';
</script>

{#if toast.text}
  <div class="toast" role="status">
    <span>{toast.text}</span>
    {#if toast.action}<a class="btn small" href={toast.href} onclick={() => (toast.text = '')}>{toast.action}</a>{/if}
    <button class="btn ghost small" aria-label="Close" onclick={() => (toast.text = '')}>✕</button>
  </div>
{/if}

<style>
  .toast { position: fixed; right: var(--s6); bottom: var(--s6); z-index: 80; display: flex; align-items: center; gap: var(--s3);
    background: var(--bg-raised); box-shadow: var(--e1); border: 1px solid var(--raised-border); border-radius: var(--r2);
    padding: var(--s3) var(--s4); }
</style>
