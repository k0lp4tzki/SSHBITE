<script lang="ts">
  // The one badge (design-revision §3.2): level meter + label on the role tint, 20 px, radius 4, 12/16 500.
  // compact = count form for count columns: meter and number without tint, the label for screen readers.
  import Meter from './Meter.svelte';
  import { LEVEL } from '../lib/format';
  let { role, label, count = null, compact = false }: { role: string; label: string; count?: number | null; compact?: boolean } = $props();
</script>
{#if compact}
  <span class="badge compact sev-{role}" title="{count} {label}"><Meter level={LEVEL[role] ?? 0} />{count}<span class="sr-only"> {label}</span></span>
{:else}
  <span class="badge sev-{role}"><Meter level={LEVEL[role] ?? 0} />{label}{#if count !== null}&nbsp;{count}{/if}</span>
{/if}
