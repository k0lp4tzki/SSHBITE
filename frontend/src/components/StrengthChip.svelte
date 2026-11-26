<script lang="ts">
  // Key strength (design-revision §3.2): Critical and Weak as badges; OK, Good and Unknown as plain text.
  import Badge from './Badge.svelte';
  import { STRENGTH_LABEL } from '../lib/format';
  let { strength, compact = false, count = null }: { strength: string | null | undefined; compact?: boolean; count?: number | null } = $props();
  const s = $derived(strength || 'unknown');
</script>
{#if s === 'critical' || s === 'weak'}
  <Badge role={s === 'critical' ? 'critical' : 'medium'} label={STRENGTH_LABEL[s]} count={compact ? count : null} {compact} />
{:else if s === 'good'}
  <span class="state">{#if compact}{count}{/if}<span class:sr-only={compact}>Good</span><svg class="ck" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M2.5 6.5 5 9l4.5-6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg></span>
{:else if s === 'ok'}
  <span class="state">{#if compact}{count} <span class="sr-only">OK</span>{:else}OK{/if}</span>
{:else}
  <span class="state unknown">{#if compact}{count} <span class="sr-only">Unknown</span>{:else}Unknown{/if}</span>
{/if}
