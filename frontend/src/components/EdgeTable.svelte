<script lang="ts">
  // Access / evidence edges with the Host-detail Access columns (design §4.8).
  import Fp from './Fp.svelte';
  import StrengthChip from './StrengthChip.svelte';
  import Badge from './Badge.svelte';
  import { EDGE_STATUS, FLAG_LABEL, fileLine, midTrunc, SOURCE_LABEL } from '../lib/format';
  import { hostHref, keyHref } from '../lib/links';
  // compact: the 520 px drawer - strength under the fingerprint, flag chips wrap; whatever still does not fit
  // scrolls sideways inside the drawer with the first column sticky.
  let { edges, scan, show = 'both', evidence = false, empty = 'No edges.', compact = false }:
    { edges: any[]; scan: number; show?: 'src' | 'dst' | 'both'; evidence?: boolean; empty?: string; compact?: boolean } = $props();
</script>
<div class="table-wrap sticky-first" class:compact>
  <table class="t">
    <thead>
      <tr>
        {#if show !== 'dst'}<th>From</th>{/if}
        {#if show !== 'src'}<th>To</th>{/if}
        {#if evidence}<th>Source</th><th>File:line</th>{:else}<th>Key</th><th>Status</th><th>Effective</th><th>Flags</th>{/if}
      </tr>
    </thead>
    <tbody>
      {#each edges as e (e.id)}
        <tr>
          {#if show !== 'dst'}
            <td class="nowrap ent">
              {#if e.src_host_id === null}
                <span class="state unknown">Unknown origin</span>
              {:else}<a href={hostHref(scan, e.src_host_id)}>{e.src}</a>{#if e.src_user}<span class="usr"><span class="muted">:</span>{e.src_user}</span>{:else if evidence}<span class="usr muted">:(system)</span>{/if}{/if}
            </td>
          {/if}
          {#if show !== 'src'}
            <td class="nowrap"><a class="plain" href={hostHref(scan, e.dst_host_id)}>{e.dst}</a>{#if e.dst_user}<span class="muted">:</span>{e.dst_user}{/if}</td>
          {/if}
          {#if evidence}
            <td>{SOURCE_LABEL[e.evidence_source] ?? e.evidence_source ?? '–'}</td>
            <td class="mono nowrap" title={fileLine(e.evidence_file, e.evidence_line)}>{midTrunc(fileLine(e.evidence_file, e.evidence_line), compact ? 30 : 48) || '–'}</td>
          {:else}
            <td class="nowrap"><span class="kr" class:stack={compact}><Fp fp={e.fp} href={keyHref(scan, e.fp)} /><StrengthChip strength={e.strength} /></span></td>
            <td class="nowrap">{#if e.status === 'unknown_origin' && e.effective}<Badge role="high" label={EDGE_STATUS[e.status]} />{:else}<span class="state" class:muted={e.status === 'restricted_blocked' || !e.effective}>{EDGE_STATUS[e.status] ?? e.status}</span>{/if}</td>
            <td>{e.effective ? 'yes' : 'no'}</td>
            <td class="flags"><span class="chips">{#each e.flags as f}<span class="kchip">{FLAG_LABEL[f] ?? f}</span>{/each}{#if e.from_patterns?.length}<span class="kchip opt" title={`from="${e.from_patterns.join(',')}"`}>from="{e.from_patterns.join(',').slice(0, 40)}"</span>{/if}</span></td>
          {/if}
        </tr>
      {:else}
        <tr><td class="empty" colspan="8">{empty}</td></tr>
      {/each}
    </tbody>
  </table>
</div>
<style>
  .usr { font-weight: 400; }
  .kr { display: inline-flex; align-items: center; gap: var(--s3); flex-wrap: nowrap; }
  .kr.stack { flex-direction: column; align-items: flex-start; gap: var(--s1); }
  .flags { min-width: 96px; }
  .compact :global(table.t th), .compact :global(table.t td) { padding-left: var(--s3); padding-right: var(--s3); }
  .compact .flags { min-width: 0; max-width: 120px; }
</style>
