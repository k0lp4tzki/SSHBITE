<script lang="ts">
  // Fingerprint (design §6.2): short "SHA256:abcd…wxyz" or full in groups of 4; copying yields the exact string.
  import CopyButton from './CopyButton.svelte';
  let { fp, full = false, href = '', copy = true }: { fp: string | null | undefined; full?: boolean; href?: string; copy?: boolean } = $props();
  const body = $derived(fp ? fp.replace(/^SHA256:/, '') : '');
  const short = $derived(body.length > 9 ? `${body.slice(0, 4)}…${body.slice(-4)}` : body);
  const grouped = $derived(body.match(/.{1,4}/g)?.join(' ') ?? body);
</script>

{#if !fp}
  <span class="muted italic">fingerprint unknown</span>
{:else}
  <span class="fp-host" title={fp}>
    {#if href}
      <a {href} class="fp mono"><span class="muted">SHA256:</span>{full ? grouped : short}</a>
    {:else}
      <span class="fp mono"><span class="muted">SHA256:</span>{full ? grouped : short}</span>
    {/if}
    {#if copy}<CopyButton text={fp} label="Copy fingerprint" visible={full} />{/if}
  </span>
{/if}

<style>
  .fp-host { display: inline-flex; align-items: center; gap: var(--s1); white-space: nowrap; max-width: 100%; }
  .fp { font-size: 13px; line-height: 18px; overflow-wrap: anywhere; white-space: normal; }
</style>
