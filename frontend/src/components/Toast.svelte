<script lang="ts">
  import { toast } from '../lib/state.svelte';
</script>

{#if toast.text}
  <div class="toast" role="status">
    <span>{toast.text}</span>
    {#if toast.action}<a class="btn small" href={toast.href} onclick={() => (toast.text = '')}>{toast.action}</a>{/if}
    <button class="btn ghost small icon" aria-label="Close" onclick={() => (toast.text = '')}><svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M3 3l6 6M9 3l-6 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" /></svg></button>
  </div>
{/if}

<style>
  .toast { position: fixed; right: var(--s6); bottom: var(--s6); z-index: 80; display: flex; align-items: center; gap: var(--s3);
    background: var(--bg-raised); box-shadow: var(--e1); border: 1px solid var(--border-subtle); border-radius: var(--r3);
    padding: var(--s3) var(--s4); font-size: 14px; }
  .icon { width: 24px; }
</style>
