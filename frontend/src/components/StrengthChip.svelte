<script lang="ts">
  import Glyph from './Glyph.svelte';
  import { STRENGTH_GLYPH, STRENGTH_LABEL, STRENGTH_SEV } from '../lib/format';
  let { strength, compact = false, count = null }: { strength: string | null | undefined; compact?: boolean; count?: number | null } = $props();
  const s = $derived(strength || 'unknown');
</script>

{#if compact}
  <span class="badge compact sev-{STRENGTH_SEV[s]}" title="{STRENGTH_LABEL[s]}"><Glyph kind={STRENGTH_GLYPH[s]} />{count ?? ''}<span class="sr-only"> {STRENGTH_LABEL[s]}</span></span>
{:else}
  <span class="badge sev-{STRENGTH_SEV[s]}"><Glyph kind={STRENGTH_GLYPH[s]} />{STRENGTH_LABEL[s]}</span>
{/if}
