<script lang="ts">
  // Scans (design §4.3): snapshots; pick two to compare.
  import { navigate } from '../lib/router.svelte';
  import { scans, loadScans } from '../lib/state.svelte';
  import { fmtDuration, fmtTime, n, utcTitle } from '../lib/format';
  import PageHead from '../components/PageHead.svelte';
  import Field from '../components/Field.svelte';
  import CodeBlock from '../components/CodeBlock.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import Badge from '../components/Badge.svelte';

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

</script>

<PageHead title="Scans">
  {#snippet fields()}
    <Field label="Stored scans" value={scans.items.length} />
    <Field label="Selected" value="{selected.length} of 2" />
  {/snippet}
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
          <th class="r">Hosts</th><th class="r">Critical</th><th class="r">High</th><th class="r">Access edges</th>
        </tr></thead>
        <tbody>
          {#each scans.items as s (s.id)}
            <tr class="clickable" class:selected={selected.includes(s.id)} onclick={(e) => { if (!(e.target as HTMLElement).closest('input,a,label')) navigate(`/s/${s.id}/`); }}>
              <td><label class="check"><input type="checkbox" checked={selected.includes(s.id)} onchange={() => toggle(s.id)} aria-label="Select scan #{s.id}" /></label></td>
              <td class="r num ent"><a href="/s/{s.id}/">#{s.id}</a></td>
              <td>{#if s.label}{s.label}{:else}<span class="muted">–</span>{/if} {#if s.synthetic}<span class="chip">Synthetic</span>{/if}</td>
              <td class="nowrap" title={utcTitle(s.started_at)}>{fmtTime(s.started_at)}</td>
              <td class="r num">{s.finished_at ? fmtDuration(s.started_at, s.finished_at) : '–'}</td>
              <td>{#if s.status === 'running'}<span class="state run"><span class="pulse" aria-hidden="true"></span>Running</span>{:else if s.status === 'completed'}<span class="state">Completed</span>{:else}<Badge role="critical" label={s.status === 'failed' ? 'Failed' : 'Aborted'} />{/if}</td>
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
  .run { color: var(--accent); }
  .pulse { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); animation: pulse 1.6s ease-in-out infinite; }
  @keyframes pulse { 50% { opacity: .3; } }
  .emptybox { max-width: 360px; margin: 0 auto; display: flex; flex-direction: column; gap: var(--s3); }
</style>
