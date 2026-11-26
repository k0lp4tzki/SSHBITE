<script lang="ts">
  // Finding rows (design §4.11): two lines - severity, title, location, recommendation / fingerprint, key, detail.
  import SevBadge from './SevBadge.svelte';
  import Fp from './Fp.svelte';
  import KeyType from './KeyType.svelte';
  import { endTrunc, fileLine, midTrunc, ruleTitle } from '../lib/format';
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
            <div class="l1 nowrap">{ruleTitle(f.rule, f)}</div>
            <div class="l2 row">
              {#if f.fp}<Fp fp={f.fp} href={keyHref(scan, f.fp)} /><KeyType alg={f.alg} bits={f.bits} />{/if}
              {#if f.label}<span class="meta secondary" title={f.label}>“{endTrunc(f.label, 22)}”</span>{/if}
            </div>
          </td>
          <td class="loc">
            <div class="l1 mono nowrap">
              {#if f.host}<a href={hostHref(scan, f.host_id)} title={f.host}>{endTrunc(f.host, 28)}</a>{#if f.username}<span class="muted">{" · "}</span><span title={f.username}>{endTrunc(f.username, 20)}</span>{/if}{:else}<span class="muted">all hosts</span>{/if}
            </div>
            <div class="l2 mono meta secondary" title={fileLine(f.file, f.line)}>{midTrunc(fileLine(f.file, f.line), 40)}</div>
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
  /* Recommendation takes the remaining width and truncates (full text in title), so it stays visible at
     1280 px; below that the table scrolls inside its panel with every column readable (design §9). */
  .rec { width: 100%; max-width: 0; min-width: 220px; }
  .rec .trunc { display: block; }
  .loc { white-space: nowrap; }
  .l2.row { flex-wrap: nowrap; white-space: nowrap; }
  .mt { margin-top: var(--s3); }
</style>
