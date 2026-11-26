<script lang="ts">
  // One context field: label (12 muted) above the value (13 primary).
  import type { Snippet } from 'svelte';
  let { label, value = '', title = '', children = undefined }: { label: string; value?: string | number; title?: string; children?: Snippet } = $props();
</script>
<div><dt>{label}</dt><dd title={title || undefined}>{#if children}{@render children()}{:else}{value}{/if}</dd></div>
