<script lang="ts">
  // Scans (design §4.3): snapshots; pick two to compare.
  import { navigate } from '../lib/router.svelte';
  import { scans, loadScans } from '../lib/state.svelte';
  import { fmtDuration, fmtTime, n, utcTitle } from '../lib/format';
  import PageHead from '../components/PageHead.svelte';
  import CodeBlock from '../components/CodeBlock.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import Glyph from '../components/Glyph.svelte';

  let selected = $state<number[]>([]);
  function toggle(id: number) {
    if (selected.includes(id)) selected = selected.filter((x) => x !== id);
    else selected = [...selected, id].slice(-2);
  }
  function compare() {
    if (selected.length !== 2) return;
    const [a, b] = [...selected].sort((x, y) => x - y);
    navigate(`/diff?a=${a}&b=${b}`);
  }
  const STATUS: Record<string, [string, string, string]> = {
    running: ['Running', 'run', 'dot'], completed: ['Completed', 'sev-low', 'dot'], failed: ['Failed', 'sev-critical', 'critical'],
    aborted: ['Aborted', 'sev-critical', 'critical'],
  };
</script>

<PageHead title="Scans">
  {#snippet actions()}
    <span title={selected.length === 2 ? '' : 'Select two scans to compare.'}>
      <button class="btn primary" disabled={selected.length !== 2} onclick={compare}>Compare selected ({selected.length})</button>
    </span>
  {/snippet}
</PageHead>

{#if scans.error}
  <ErrorPanel thing="scans" message={scans.error} retry={loadScans} />
{:else if !scans.loaded}
  <Skeleton />
{:else}
  <section class="panel flush">
    <div class="table-wrap">
      <table class="t">
        <thead><tr>
          <th><span class="sr-only">Select</span></th><th class="r">#</th><th>Label</th><th>Started</th><th class="r">Duration</th><th>Status</th>
          <th class="r">Hosts</th><th class="r">Crit</th><th class="r">High</th><th class="r">Access edges</th>
        </tr></thead>
        <tbody>
          {#each scans.items as s (s.id)}
            {@const st = STATUS[s.status] ?? [s.status, 'sev-info', 'info']}
            <tr class="clickable" class:selected={selected.includes(s.id)} onclick={(e) => { if (!(e.target as HTMLElement).closest('input,a,label')) navigate(`/s/${s.id}/`); }}>
              <td><label class="check"><input type="checkbox" checked={selected.includes(s.id)} onchange={() => toggle(s.id)} aria-label="Select scan #{s.id}" /></label></td>
              <td class="r num"><a href="/s/{s.id}/">#{s.id}</a></td>
              <td>{#if s.label}{s.label}{:else}<span class="muted">–</span>{/if} {#if s.synthetic}<span class="chip syn">Synthetic</span>{/if}</td>
              <td class="nowrap" title={utcTitle(s.started_at)}>{fmtTime(s.started_at)}</td>
              <td class="r num">{s.finished_at ? fmtDuration(s.started_at, s.finished_at) : '–'}</td>
              <td><span class="badge {st[1]}">{#if s.status === 'running'}<span class="pulse" aria-hidden="true"></span>{:else}<Glyph kind={st[2]} />{/if}{st[0]}</span></td>
              <td class="r num">{s.counts?.hosts_total !== undefined ? n(s.counts.hosts_total) : '–'}</td>
              <td class="r num">{s.counts?.findings ? n(s.counts.findings.critical ?? 0) : '–'}</td>
              <td class="r num">{s.counts?.findings ? n(s.counts.findings.high ?? 0) : '–'}</td>
              <td class="r num">{s.counts?.access_edges !== undefined ? n(s.counts.access_edges) : '–'}</td>
            </tr>
          {:else}
            <tr><td class="empty" colspan="10">
              <div class="emptybox">No scans yet. Run sshbite scan. <CodeBlock cmd="sshbite scan" /></div>
            </td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
{/if}

<style>
  .run { --c: var(--accent); --cb: var(--accent-subtle); }
  .pulse { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); animation: pulse 1.6s ease-in-out infinite; }
  @keyframes pulse { 50% { opacity: .3; } }
  .syn { background: var(--accent-subtle); color: var(--accent); }
  .emptybox { max-width: 360px; margin: 0 auto; display: flex; flex-direction: column; gap: var(--s3); }
</style>
