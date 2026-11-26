<script lang="ts">
  // Scan-state notices under the page title (design §3).
  import Strip from './Strip.svelte';
  import { latestCompleted, live, runningScan } from '../lib/state.svelte';
  import { n, plural } from '../lib/format';
  let { scan, partial = false }: { scan: any; partial?: boolean } = $props();
  const running = $derived(runningScan());
  const p = $derived(live.scan?.progress ?? {});
  const partialCount = $derived(scan?.counts?.hosts?.partial ?? 0);
  const latest = $derived(latestCompleted());
</script>

<div class="notices">
  {#if running && running.id !== scan?.id}
    <Strip role="info">Scan #{running.id} is running – depth {p.depth ?? 0}, {n(p.queued ?? 0)} queued, {n(p.running ?? 0)} running, {n(p.done ?? 0)} done. Data shown is from scan #{scan?.id}.</Strip>
  {/if}
  {#if scan && (scan.status === 'failed' || scan.status === 'aborted')}
    <Strip role="error">Scan #{scan.id} {scan.status === 'failed' ? 'failed' : 'was aborted'}: {scan.counts?.error ?? 'no error recorded'}. It has no host data.
      {#if latest}<a href="/s/{latest.id}/">Open latest completed scan</a>{/if}</Strip>
  {/if}
  {#if partial && partialCount > 0}
    <Strip role="warning">{plural(partialCount, 'host was', 'hosts were')} scanned partially; their data is incomplete. <a href="/s/{scan.id}/hosts?status=partial">Show partial hosts</a></Strip>
  {/if}
</div>

<style>
  .notices { display: flex; flex-direction: column; gap: var(--s3); }
  .notices:empty { display: none; }
</style>
