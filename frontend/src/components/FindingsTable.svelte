<script lang="ts">
  // Finding rows (design §4.11): two lines - severity, title, location, recommendation / fingerprint, key, detail.
  import SevBadge from './SevBadge.svelte';
  import Fp from './Fp.svelte';
  import KeyType from './KeyType.svelte';
  import { fileLine, midTrunc, ruleTitle } from '../lib/format';
  import { detailText, hostHref, keyHref } from '../lib/links';

  let { items, scan, empty, children = undefined, target = '' }: { items: any[]; scan: number; empty: string; children?: any; target?: string } = $props();
</script>

<div class="table-wrap">
  <table class="t ft">
    <thead><tr><th class="c-sev">Severity</th><th>Finding</th><th>Location</th><th>Recommendation</th></tr></thead>
    <tbody>
      {#each items as f (f.id)}
        <tr id="finding-{f.id}" class:target={target === `finding-${f.id}`}>
          <td class="c-sev"><SevBadge severity={f.severity} /></td>
          <td>
            <div class="l1">{ruleTitle(f.rule, f)}</div>
            <div class="l2 row">
              {#if f.fp}<Fp fp={f.fp} href={keyHref(scan, f.fp)} /><KeyType alg={f.alg} bits={f.bits} />{/if}
              {#if f.label}<span class="meta secondary">“{f.label}”</span>{/if}
            </div>
          </td>
          <td class="loc">
            <div class="l1 mono nowrap">
              {#if f.host}<a href={hostHref(scan, f.host_id)}>{f.host}</a>{#if f.username}<span class="muted">{" · "}</span>{f.username}{/if}{:else}<span class="muted">all hosts</span>{/if}
            </div>
            <div class="l2 mono meta secondary" title={fileLine(f.file, f.line)}>{midTrunc(fileLine(f.file, f.line), 44)}</div>
          </td>
          <td class="rec">
            <div class="l1 trunc" title={f.recommendation}>{f.recommendation}</div>
            <div class="l2 meta secondary trunc" title={detailText(f)}>{detailText(f)}</div>
          </td>
        </tr>
      {:else}
        <tr><td class="empty" colspan="4">{empty}{#if children}<div class="mt">{@render children()}</div>{/if}</td></tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .ft td { height: 52px; vertical-align: top; padding-top: var(--s2); padding-bottom: var(--s2); }
  .c-sev { width: 96px; }
  .l1 { min-height: 20px; line-height: 20px; }
  .l2 { min-height: 20px; line-height: 20px; gap: var(--s3); flex-wrap: nowrap; }
  .rec { max-width: 380px; }
  .rec .trunc { display: block; }
  .loc { white-space: nowrap; }
  .mt { margin-top: var(--s3); }
</style>
