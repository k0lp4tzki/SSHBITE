<script lang="ts">
  // Notice strip (design-revision §4): role tint, level meter of the role, text 13/20; info uses a circled i.
  import type { Snippet } from 'svelte';
  import Meter from './Meter.svelte';
  let { role = 'info', children }: { role?: 'info' | 'warning' | 'error' | 'high'; children: Snippet } = $props();
  const level = $derived(role === 'warning' ? 2 : role === 'error' ? 4 : role === 'high' ? 3 : -1);
</script>
<div class="strip {role}" role={role === 'error' ? 'alert' : 'status'}>
  <span class="gl">{#if level >= 0}<Meter {level} />{:else}<svg class="glyph" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><circle cx="6" cy="6" r="5.25" fill="none" stroke="currentColor" stroke-width="1.5" /><path d="M6 5.2v3.6M6 3.2v.4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" /></svg>{/if}</span>
  <div class="body">{@render children()}</div>
</div>
<style>
  .body { flex: 1; min-width: 0; }
</style>
