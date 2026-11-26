<script lang="ts">
  // 12 px severity / strength glyphs (design §2.2); shape carries the meaning, colour is the third channel.
  let { kind, size = 12 }: { kind: string; size?: number } = $props();
</script>

<svg class="glyph" width={size} height={size} viewBox="0 0 12 12" aria-hidden="true" focusable="false">
  {#if kind === 'critical'}
    <polygon points="3.5,0.5 8.5,0.5 11.5,3.5 11.5,8.5 8.5,11.5 3.5,11.5 0.5,8.5 0.5,3.5" fill="currentColor" />
    <rect x="5.2" y="2.4" width="1.6" height="4.6" class="on" />
    <rect x="5.2" y="8.1" width="1.6" height="1.6" class="on" />
  {:else if kind === 'high'}
    <polygon points="6,0.6 11.6,11 0.4,11" fill="currentColor" />
  {:else if kind === 'medium'}
    <polygon points="6,0.4 11.6,6 6,11.6 0.4,6" fill="currentColor" />
  {:else if kind === 'low'}
    <circle cx="6" cy="6" r="4.75" fill="none" stroke="currentColor" stroke-width="1.5" />
  {:else if kind === 'info'}
    <rect x="1.25" y="1.25" width="9.5" height="9.5" fill="none" stroke="currentColor" stroke-width="1.5" />
  {:else if kind === 'good'}
    <circle cx="6" cy="6" r="5.25" fill="none" stroke="currentColor" stroke-width="1.5" />
    <path d="M3.4 6.2 L5.3 8 L8.7 4.2" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
  {:else if kind === 'dot'}
    <circle cx="6" cy="6" r="5" fill="currentColor" />
  {:else if kind === 'unknown'}
    <circle cx="6" cy="6" r="5.1" fill="none" stroke="currentColor" stroke-width="1.3" stroke-dasharray="2 1.6" />
    <path d="M4.6 4.7 C4.6 3.1 7.4 3.1 7.4 4.7 C7.4 5.8 6 5.8 6 7" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" />
    <circle cx="6" cy="8.7" r=".75" fill="currentColor" />
  {:else if kind === 'added'}
    <path d="M6 1.5 V10.5 M1.5 6 H10.5" stroke="currentColor" stroke-width="1.8" />
  {:else if kind === 'removed'}
    <path d="M1.5 6 H10.5" stroke="currentColor" stroke-width="1.8" />
  {:else if kind === 'changed'}
    <path d="M1 7 C3 3 5 3 6 6 C7 9 9 9 11 5" fill="none" stroke="currentColor" stroke-width="1.6" />
  {/if}
</svg>

<style>
  .on { fill: var(--bg-surface); }
  :global(:root[data-theme='light']) .on { fill: #ffffff; }
</style>
