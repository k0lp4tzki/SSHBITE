<script lang="ts">
  import Glyph from './Glyph.svelte';
  import { SEV_LABEL } from '../lib/format';
  let { severity, count = null, compact = false }: { severity: string; count?: number | null; compact?: boolean } = $props();
</script>

{#if compact}
  <span class="badge compact sev-{severity}" title="{count} {SEV_LABEL[severity]}"><Glyph kind={severity} />{count}<span class="sr-only"> {SEV_LABEL[severity]}</span></span>
{:else}
  <span class="badge sev-{severity}"><Glyph kind={severity} />{SEV_LABEL[severity] ?? severity}{#if count !== null}&nbsp;{count}{/if}</span>
{/if}
