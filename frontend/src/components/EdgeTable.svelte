<script lang="ts">
  // Access / evidence edges with the Host-detail Access columns (design §4.8).
  import Fp from './Fp.svelte';
  import StrengthChip from './StrengthChip.svelte';
  import Glyph from './Glyph.svelte';
  import { EDGE_STATUS, FLAG_LABEL, fileLine, SOURCE_LABEL } from '../lib/format';
  import { hostHref, keyHref } from '../lib/links';

  let { edges, scan, show = 'both', evidence = false, empty = 'No edges.' }:
    { edges: any[]; scan: number; show?: 'src' | 'dst' | 'both'; evidence?: boolean; empty?: string } = $props();

  function statusCls(s: string, eff: boolean) {
    if (s === 'restricted_blocked' || !eff) return 'sev-info';
    if (s === 'unknown_origin') return 'sev-high';
    return 'sev-low';
  }
</script>

<div class="table-wrap">
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
            <td class="mono nowrap">
              {#if e.src_host_id === null}
                <span class="sev-info unk"><Glyph kind="unknown" /></span><span class="muted">Unknown origin</span>
              {:else}<a href={hostHref(scan, e.src_host_id)}>{e.src}</a>{#if e.src_user}<span class="muted">:</span>{e.src_user}{:else if evidence}<span class="muted">:(system)</span>{/if}{/if}
            </td>
          {/if}
          {#if show !== 'src'}
            <td class="mono nowrap"><a href={hostHref(scan, e.dst_host_id)}>{e.dst}</a>{#if e.dst_user}<span class="muted">:</span>{e.dst_user}{/if}</td>
          {/if}
          {#if evidence}
            <td>{SOURCE_LABEL[e.evidence_source] ?? e.evidence_source ?? '–'}</td>
            <td class="mono" title={fileLine(e.evidence_file, e.evidence_line)}>{fileLine(e.evidence_file, e.evidence_line) || '–'}</td>
          {:else}
            <td class="nowrap"><span class="row nowrap"><Fp fp={e.fp} href={keyHref(scan, e.fp)} /><StrengthChip strength={e.strength} /></span></td>
            <td><span class="badge {statusCls(e.status, e.effective)}">{EDGE_STATUS[e.status] ?? e.status}</span></td>
            <td>{e.effective ? 'yes' : 'no'}</td>
            <td><span class="chips">{#each e.flags as f}<span class="kchip">{FLAG_LABEL[f] ?? f}</span>{/each}{#if e.from_patterns?.length}<span class="kchip" title={`from="${e.from_patterns.join(',')}"`}>from="{e.from_patterns.join(',').slice(0, 40)}"</span>{/if}</span></td>
          {/if}
        </tr>
      {:else}
        <tr><td class="empty" colspan="8">{empty}</td></tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .unk { color: var(--c); margin-right: var(--s2); }
  .row { gap: var(--s2); flex-wrap: nowrap; }
</style>
