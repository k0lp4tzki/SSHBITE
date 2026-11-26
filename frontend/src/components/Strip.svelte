<script lang="ts">
  import type { Snippet } from 'svelte';
  import Glyph from './Glyph.svelte';
  let { role = 'info', glyph = '', children }: { role?: 'info' | 'warning' | 'error' | 'high'; glyph?: string; children: Snippet } = $props();
  const g = $derived(glyph || (role === 'warning' ? 'medium' : role === 'error' ? 'critical' : role === 'high' ? 'high' : ''));
  const cls = $derived(role === 'warning' ? 'sev-medium' : role === 'error' ? 'sev-critical' : role === 'high' ? 'sev-high' : '');
</script>

<div class="strip {role}" role={role === 'error' ? 'alert' : 'status'}>
  {#if g}<span class={cls}><span class="gl"><Glyph kind={g} /></span></span>{/if}
  <div class="body">{@render children()}</div>
</div>

<style>
  .gl { color: var(--c); display: inline-flex; padding-top: 4px; }
  .body { flex: 1; min-width: 0; }
</style>
