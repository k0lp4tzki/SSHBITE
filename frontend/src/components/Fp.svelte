<script lang="ts">
  // Fingerprint (design §6.2, revision §3.4): Mono; short "SHA256:abcd…wxyz" or full in groups of 4; the SHA256:
  // prefix in text.muted; copying yields the exact string.
  import CopyButton from './CopyButton.svelte';
  let { fp, full = false, href = '', copy = true, size = 12 }: { fp: string | null | undefined; full?: boolean; href?: string; copy?: boolean; size?: 12 | 13 } = $props();
  const body = $derived(fp ? fp.replace(/^SHA256:/, '') : '');
  const short = $derived(body.length > 9 ? `${body.slice(0, 4)}…${body.slice(-4)}` : body);
  const grouped = $derived(body.match(/.{1,4}/g)?.join(' ') ?? body);   // thin spaces: copying yields the exact string
</script>
{#if !fp}
  <span class="state unknown">fingerprint unknown</span>
{:else}
  <span class="fp-host" class:full title={fp}>
    {#if href}
      <a {href} class="fp mono" class:s13={size === 13}><span class="pre">SHA256:</span>{full ? grouped : short}</a>
    {:else}
      <span class="fp mono" class:s13={size === 13}><span class="pre">SHA256:</span>{full ? grouped : short}</span>
    {/if}
    {#if copy}<CopyButton text={fp} label="Copy fingerprint" visible={full} />{/if}
  </span>
{/if}
<style>
  /* the short form never wraps (it is 18 characters); the full form breaks only between its groups of 4 */
  .fp-host { display: inline-flex; align-items: center; gap: var(--s1); white-space: nowrap; flex: none; }
  .fp { font-size: 12px; line-height: 20px; white-space: nowrap; }
  .fp.s13 { font-size: 13px; }
  .pre { color: var(--text-muted); }
  a.fp:hover .pre { color: inherit; }
  .fp-host.full { flex: 0 1 auto; max-width: 100%; }
  .fp-host.full .fp { white-space: normal; overflow-wrap: normal; }
</style>
