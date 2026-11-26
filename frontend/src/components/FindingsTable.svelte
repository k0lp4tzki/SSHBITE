<script lang="ts">
  // Finding rows (design-revision §5.5): at least 56 px, every cell top aligned, 10 px top and bottom.
  // Severity | Finding (title + detail) | Location (host, user, file:line) | Key (short fp, type) | Recommendation (2 lines).
  import SevBadge from './SevBadge.svelte';
  import Fp from './Fp.svelte';
  import KeyType from './KeyType.svelte';
  import { endTrunc, fileLine, midTrunc, ruleTitle } from '../lib/format';
  import { detailText, hostHref, keyHref } from '../lib/links';
  let { items, scan, empty, children = undefined, target = '' }: { items: any[]; scan: number; empty: string; children?: any; target?: string } = $props();
</script>
<div class="table-wrap">
  <table class="t ft">
    <thead><tr><th class="c-sev">Severity</th><th class="c-f">Finding</th><th class="c-loc">Location</th><th class="c-key">Key</th><th class="c-rec">Recommendation</th></tr></thead>
    <tbody>
      {#each items as f (f.id)}
        {@const det = detailText(f)}
        <tr id="finding-{f.id}" class:target={target === `finding-${f.id}`}>
          <td class="c-sev"><SevBadge severity={f.severity} /></td>
          <td class="c-f">
            <div class="l1 ttl">{ruleTitle(f.rule, f)}</div>
            {#if det || f.label}<div class="l2" title={det}>{#if f.label}<span class="lab">“{endTrunc(f.label, 28)}”</span> {/if}{det}</div>{/if}
          </td>
          <td class="loc">
            <div class="l1 nowrap">
              {#if f.host}<a class="hl" href={hostHref(scan, f.host_id)} title={f.host}>{endTrunc(f.host, 24)}</a>{#if f.username}<span class="usr" title={f.username}>{endTrunc(f.username, 16)}</span>{/if}{:else}<span class="muted">all hosts</span>{/if}
            </div>
            {#if f.file}<div class="l2 mono" title={fileLine(f.file, f.line)}>{midTrunc(fileLine(f.file, f.line), 30)}</div>{/if}
          </td>
          <td class="c-key">
            {#if f.fp}<div class="l1 nowrap"><Fp fp={f.fp} href={keyHref(scan, f.fp)} /></div><div class="l2"><KeyType alg={f.alg} bits={f.bits} /></div>{:else}<span class="muted">–</span>{/if}
          </td>
          <td class="rec">
            <div class="l1 clamp" title={f.recommendation}>{f.recommendation}</div>
          </td>
        </tr>
      {:else}
        <tr><td class="empty" colspan="5">{empty}{#if children}<div class="mt">{@render children()}</div>{/if}</td></tr>
      {/each}
    </tbody>
  </table>
</div>
<style>
  .ft td { height: 56px; vertical-align: top; padding-top: 10px; padding-bottom: 10px; }
  .ft td.empty { vertical-align: middle; }
  .c-sev { width: 112px; }
  .l1 { line-height: 20px; }
  .ttl { font-weight: 500; }
  .l2 { font-size: 12px; line-height: 16px; color: var(--text-secondary); margin-top: 2px; }
  .c-f { min-width: 230px; }
  .c-f .l2 { display: -webkit-box; -webkit-line-clamp: 2; line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; overflow-wrap: anywhere; }
  .lab { color: var(--text-primary); }
  .loc { white-space: nowrap; }
  .hl { font-weight: 500; }
  .usr { color: var(--text-secondary); margin-left: var(--s3); }
  .c-key { white-space: nowrap; width: 1%; }
  .c-key .l2 { margin-top: 2px; }
  /* Recommendation takes the remaining width: at most two lines, then "…" (full text in title) */
  .rec { width: 36%; max-width: 0; min-width: 180px; }
  .clamp { display: -webkit-box; -webkit-line-clamp: 2; line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
  .mt { margin-top: var(--s3); }
</style>
