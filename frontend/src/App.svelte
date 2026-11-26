<script lang="ts">
  import { onMount } from 'svelte';
  import { navigate, route } from './lib/router.svelte';
  import { diffPair, lastScan, latestCompleted, rememberScan, loadScans, loadSession, scans, session, startLivePolling } from './lib/state.svelte';
  import Shell from './components/Shell.svelte';
  import NoScan from './components/NoScan.svelte';
  import Login from './screens/Login.svelte';
  import Dashboard from './screens/Dashboard.svelte';
  import Scans from './screens/Scans.svelte';
  import Crawl from './screens/Crawl.svelte';
  import Heatmap from './screens/Heatmap.svelte';
  import Graph from './screens/Graph.svelte';
  import Hosts from './screens/Hosts.svelte';
  import HostDetail from './screens/HostDetail.svelte';
  import Keys from './screens/Keys.svelte';
  import KeyDetail from './screens/KeyDetail.svelte';
  import Findings from './screens/Findings.svelte';
  import Diff from './screens/Diff.svelte';

  let ready = $state(false);

  async function boot() {
    const ok = await loadSession();
    if (!ok) {
      if (route.path !== '/login') navigate('/login' + (route.path !== '/' ? `?next=${encodeURIComponent(route.path + route.search)}` : ''), true);
      ready = true;
      return;
    }
    await loadScans();
    startLivePolling();
    ready = true;
  }
  onMount(boot);

  // after login the Login screen calls this
  async function loggedIn(next: string) {
    await boot();
    navigate(next && next.startsWith('/') && !next.startsWith('//') ? next : '/', true);
  }

  const parsed = $derived.by(() => {
    const p = route.path;
    let m;
    if (p === '/login') return { screen: 'login' };
    if (p === '/scans') return { screen: 'scans' };
    if (p === '/diff') return { screen: 'diff' };
    if ((m = p.match(/^\/s\/(\d+)\/?$/))) return { screen: 'dashboard', scan: +m[1] };
    if ((m = p.match(/^\/s\/(\d+)\/(heatmap|graph|hosts|keys|findings|crawl)\/?$/))) return { screen: m[2], scan: +m[1] };
    if ((m = p.match(/^\/s\/(\d+)\/hosts\/(\d+)\/?$/))) return { screen: 'host', scan: +m[1], id: +m[2] };
    if ((m = p.match(/^\/s\/(\d+)\/keys\/([^/]+)\/?$/))) return { screen: 'key', scan: +m[1], fp: decodeURIComponent(m[2]) };
    if (p === '/' || p === '') return { screen: 'home' };
    return { screen: 'notfound' };
  });

  // "/" goes to the latest completed scan
  $effect(() => {
    if (ready && session.username && parsed.screen === 'home' && scans.loaded) {
      const l = latestCompleted() ?? scans.items[0];
      if (l) navigate(`/s/${l.id}/`, true);
    }
  });

  const scanId = $derived((parsed as any).scan ?? null);
  const scan = $derived(scanId !== null ? scans.items.find((s) => s.id === scanId) ?? null : null);
  $effect(() => { if (scan) rememberScan(scan.id); });
  // /scans and /diff have no scan in the URL: the top bar keeps the scan last opened (else the latest completed)
  const topScanId = $derived(scanId ?? (parsed.screen === 'scans' || parsed.screen === 'diff'
    ? (scans.items.some((s) => s.id === lastScan.id) ? lastScan.id : latestCompleted()?.id ?? null) : null));
  const topScan = $derived(topScanId !== null ? scans.items.find((s) => s.id === topScanId) ?? null : null);
  // synthetic banner (design §3, §4.12, §10.1): the scan shown; on Diff when A or B is synthetic
  const synthetic = $derived.by(() => {
    if (parsed.screen === 'diff') {
      const [a, b] = diffPair(route.query);
      return scans.items.some((s) => (s.id === a || s.id === b) && s.synthetic);
    }
    if (parsed.screen === 'scans') return !!topScan?.synthetic;
    return !!scan?.synthetic;
  });
</script>

{#if !ready}
  <div class="boot" aria-busy="true"></div>
{:else if parsed.screen === 'login'}
  <Login onlogin={loggedIn} />
{:else if session.username}
  <Shell scanId={topScanId} {synthetic}>
    {#if parsed.screen === 'scans'}
      <Scans />
    {:else if scans.loaded && scans.items.length === 0}
      <NoScan />
    {:else if parsed.screen === 'diff'}
      <Diff />
    {:else if parsed.screen === 'home'}
      <NoScan />
    {:else if parsed.screen === 'notfound'}
      <section class="empty-state"><h2 class="section-title">Page not found</h2><p>There is no page at <span class="mono">{route.path}</span>. <a href="/">Open the dashboard</a></p></section>
    {:else if scanId !== null && scans.loaded && !scan}
      <section class="empty-state"><h2 class="section-title">Scan #{scanId} does not exist</h2><p>It may have been deleted with <span class="mono">sshbite scans delete</span>. <a href="/scans">Show all scans</a></p></section>
    {:else if scan}
      {#key scanId}
        {#if parsed.screen === 'dashboard'}<Dashboard {scan} />
        {:else if parsed.screen === 'heatmap'}<Heatmap {scan} />
        {:else if parsed.screen === 'graph'}<Graph {scan} />
        {:else if parsed.screen === 'hosts'}<Hosts {scan} />
        {:else if parsed.screen === 'host'}<HostDetail {scan} hostId={(parsed as any).id} />
        {:else if parsed.screen === 'keys'}<Keys {scan} />
        {:else if parsed.screen === 'key'}<KeyDetail {scan} fp={(parsed as any).fp} />
        {:else if parsed.screen === 'findings'}<Findings {scan} />
        {:else if parsed.screen === 'crawl'}<Crawl {scan} />
        {/if}
      {/key}
    {/if}
  </Shell>
{/if}

<style>
  .boot { min-height: 100vh; background: var(--bg-page); }
</style>
