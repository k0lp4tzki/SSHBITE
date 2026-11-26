<script lang="ts">
  // App shell (design §3): synthetic banner, sidebar, top bar with scan selector, search and user menu.
  import type { Snippet } from 'svelte';
  import { api, qs } from '../lib/api';
  import { navigate, route } from '../lib/router.svelte';
  import { scans, session, setTheme, theme, type ThemePref } from '../lib/state.svelte';
  import { fmtTime, scanTitle, utcTitle } from '../lib/format';
  import { keyHref } from '../lib/links';
  import StrengthChip from './StrengthChip.svelte';
  import Fp from './Fp.svelte';
  import Toast from './Toast.svelte';

  let { scanId = null, synthetic = false, children }: { scanId?: number | null; synthetic?: boolean; children: Snippet } = $props();

  const current = $derived(scans.items.find((s) => s.id === scanId) ?? null);
  const navScan = $derived(scanId ?? scans.items.find((s) => s.status === 'completed')?.id ?? scans.items[0]?.id ?? null);

  const NAV = [
    { key: '', label: 'Dashboard', icon: 'M2 2h5v5H2zM9 2h5v3H9zM9 7h5v7H9zM2 9h5v5H2z' },
    { key: 'heatmap', label: 'Heatmap', icon: 'M2 2h3v3H2zM6.5 2h3v3h-3zM11 2h3v3h-3zM2 6.5h3v3H2zM6.5 6.5h3v3h-3zM2 11h3v3H2z' },
    { key: 'graph', label: 'Graph', icon: 'M4 4l8 2M4 4l2 8M12 6l-6 6M2.5 2.5h3v3h-3zM10.5 4.5h3v3h-3zM4.5 10.5h3v3h-3z' },
    { key: 'hosts', label: 'Hosts', icon: 'M2 3h12v4H2zM2 9h12v4H2zM4 5h1M4 11h1' },
    { key: 'keys', label: 'Keys', icon: 'M6 8a3 3 0 1 1 0-.01M8.5 8H14M12 8v2.5M14 8v2' },
    { key: 'findings', label: 'Findings', icon: 'M8 2l6 11H2zM8 6.5v3M8 11v.5' },
  ];
  const NAV2 = [
    { href: '/scans', label: 'Scans', icon: 'M3 3h10M3 6.5h10M3 10h10M3 13.5h6' },
    { href: '/diff', label: 'Diff', icon: 'M5 2v12M11 2v12M2 5h6M8 11h6' },
  ];
  function navHref(key: string) {
    if (navScan === null) return '/';
    return `/s/${navScan}/${key}`;
  }
  function isActive(key: string) {
    const m = route.path.match(/^\/s\/\d+\/?([a-z]*)/);
    if (!m) return route.path === '/' && key === '';
    return (m[1] || '') === key;
  }

  let navOpen = $state(false);

  // ---- scan selector
  let scanMenu = $state(false);
  function pickScan(id: number) {
    scanMenu = false;
    const m = route.path.match(/^\/s\/\d+(\/.*)?$/);
    if (m) {
      let rest = m[1] ?? '/';
      // detail pages of another scan's host ids would not exist: keep the list screen
      rest = rest.replace(/^\/hosts\/\d+.*$/, '/hosts');
      // drill-down and centre stay; other filters stay as well
      navigate(`/s/${id}${rest}${route.search}`);
    } else navigate(`/s/${id}/`);
  }

  // ---- search
  let q = $state('');
  let results = $state<any>(null);
  let searchOpen = $state(false);
  let searchEl: HTMLInputElement;
  let timer: number | undefined;
  function onSearch() {
    clearTimeout(timer);
    active = -1;
    if (q.trim().length < 2) { results = null; pending = false; return; }
    pending = true;
    timer = window.setTimeout(async () => {
      const sid = navScan;
      const asked = q.trim();
      let r;
      try { r = await api('/search' + qs({ q: asked, scan: sid })); } catch { r = { hosts: [], keys: [], users: [], scan: sid }; }
      if (asked !== q.trim()) return;     // typed on meanwhile
      results = r;
      pending = false;
      active = -1;
      searchOpen = true;
    }, 200);
  }
  function go(href: string) {
    searchOpen = false;
    q = '';
    results = null;
    active = -1;
    navigate(href);
  }
  // keyboard (design §3, §8): ArrowDown/ArrowUp move the active result (aria-activedescendant), Enter opens it -
  // or the first result when none is active - and Esc closes the popover.
  let active = $state(-1);
  const options = $derived.by(() => {
    if (!results) return [] as string[];
    const sc = results.scan;
    return [
      ...results.hosts.map((h: any) => `/s/${sc}/hosts/${h.host_id}`),
      ...results.keys.map((k: any) => keyHref(sc, k.fp)),
      ...results.users.map((u: any) => `/s/${sc}/hosts/${u.host_id}?tab=users#user-${encodeURIComponent(u.username)}`),
    ];
  });
  const optId = (i: number) => `search-opt-${i}`;
  async function searchNow() {
    clearTimeout(timer);
    const sid = navScan;
    try { results = await api('/search' + qs({ q: q.trim(), scan: sid })); } catch { results = { hosts: [], keys: [], users: [], scan: sid }; }
    active = -1;
    searchOpen = true;
  }
  async function searchKey(e: KeyboardEvent) {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      if (!options.length) return;
      e.preventDefault();
      searchOpen = true;
      active = e.key === 'ArrowDown' ? Math.min(active + 1, options.length - 1) : Math.max(active - 1, 0);
      document.getElementById(optId(active))?.scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (q.trim().length < 2) return;
      if (!results || pending) { pending = false; await searchNow(); }
      if (options.length) go(options[active >= 0 ? active : 0]);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      searchOpen = false;
      active = -1;
    }
  }
  let pending = false;
  function globalKey(e: KeyboardEvent) {
    const t = e.target as HTMLElement;
    const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
    if (e.key === '/' && !typing) { e.preventDefault(); searchEl?.focus(); }
    if (e.key === 'Escape') { searchOpen = false; scanMenu = false; userMenu = false; navOpen = false; }
  }
  function closeOnOutside(e: MouseEvent) {
    const t = e.target as HTMLElement;
    if (!t.closest('.search')) searchOpen = false;
    if (!t.closest('.scansel')) scanMenu = false;
    if (!t.closest('.usermenu')) userMenu = false;
  }

  // ---- user menu
  let userMenu = $state(false);
  async function logout() {
    try { await api('/logout', { method: 'POST' }); } catch { /* the session may be gone already */ }
    session.username = '';
    navigate('/login');
  }
  const THEMES: [ThemePref, string][] = [['system', 'System'], ['light', 'Light'], ['dark', 'Dark']];
</script>

<svelte:window onkeydown={globalKey} onclick={closeOnOutside} />

<a class="skip" href="#main">Skip to content</a>
{#if synthetic}
  <div class="synth" role="note"><span>SYNTHETIC DATA – generated by <span class="mono">sshbite synth</span>, not from real hosts</span></div>
{/if}
<div class="layout" class:has-synth={synthetic}>
  <nav class="side" class:open={navOpen} aria-label="Main">
    <div class="brand"><span class="wordmark">SSHBITE</span></div>
    <ul>
      {#each NAV as it}
        <li><a href={navHref(it.key)} class:active={isActive(it.key)} aria-current={isActive(it.key) ? 'page' : undefined} title={it.label} onclick={() => (navOpen = false)}>
          <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d={it.icon} fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round" stroke-linecap="round" /></svg>
          <span class="lbl">{it.label}</span></a></li>
      {/each}
    </ul>
    <hr />
    <ul>
      {#each NAV2 as it}
        <li><a href={it.href} class:active={route.path.startsWith(it.href)} aria-current={route.path.startsWith(it.href) ? 'page' : undefined} title={it.label} onclick={() => (navOpen = false)}>
          <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d={it.icon} fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" /></svg>
          <span class="lbl">{it.label}</span></a></li>
      {/each}
    </ul>
    <div class="foot meta muted"><span class="lbl">Read-only audit · v{session.version}</span></div>
  </nav>
  {#if navOpen}<div class="scrim" onclick={() => (navOpen = false)} aria-hidden="true"></div>{/if}

  <div class="main-col">
    <header class="top">
      <button class="btn ghost icon menu-btn" aria-label="Menu" aria-expanded={navOpen} onclick={(e) => { e.stopPropagation(); navOpen = !navOpen; }}>☰</button>
      <div class="scansel">
        <button class="btn sel" aria-haspopup="listbox" aria-expanded={scanMenu} onclick={() => (scanMenu = !scanMenu)} disabled={scans.items.length === 0}
          title={current ? utcTitle(current.started_at) : ''}>
          {#if current}
            <span class="trunc">{scanTitle(current)}</span>
            {#if current.status !== 'completed'}<span class="chip st st-{current.status}">{current.status === 'running' ? 'Running' : current.status === 'failed' ? 'Failed' : 'Aborted'}</span>{/if}
          {:else if scans.items.length === 0}<span class="muted">No scans yet</span>{:else}<span>Choose a scan</span>{/if}
          <span aria-hidden="true" class="muted">▾</span>
        </button>
        {#if scanMenu}
          <ul class="popover menu" role="listbox" aria-label="Scans">
            {#each scans.items as s (s.id)}
              <li><button role="option" aria-selected={s.id === scanId} class:selected={s.id === scanId} onclick={() => pickScan(s.id)}>
                <span class="num mono">#{s.id}</span>
                <span class="trunc lbl2">{s.label || 'unlabelled'}</span>
                <span class="meta secondary nowrap" title={utcTitle(s.started_at)}>{fmtTime(s.started_at)}</span>
                {#if s.status !== 'completed'}<span class="chip st st-{s.status}">{s.status === 'running' ? 'Running' : s.status === 'failed' ? 'Failed' : 'Aborted'}</span>{/if}
                {#if s.synthetic}<span class="chip synchip">Synthetic</span>{/if}
              </button></li>
            {/each}
          </ul>
        {/if}
      </div>

      <div class="search" role="search">
        <input bind:this={searchEl} class="input" type="search" placeholder="Search hosts, keys, users" aria-label="Search hosts, keys, users"
          role="combobox" aria-autocomplete="list" aria-controls="search-results" aria-expanded={searchOpen && !!results}
          aria-activedescendant={searchOpen && active >= 0 ? optId(active) : undefined}
          bind:value={q} oninput={onSearch} onkeydown={searchKey} onfocus={() => { if (results) searchOpen = true; }} />
        <kbd class="kbd micro" aria-hidden="true">/</kbd>
        {#if searchOpen && results}
          <div class="popover results" id="search-results" role="listbox" aria-label="Search results">
            {#if !results.hosts.length && !results.keys.length && !results.users.length}
              <p class="none">Nothing matches "{q}" in scan #{results.scan}.</p>
            {:else}
              {#if results.hosts.length}
                <h3 class="micro muted">Hosts</h3>
                {#each results.hosts as h, i}<button class="res" id={optId(i)} role="option" tabindex="-1" aria-selected={active === i} class:active={active === i} onmouseenter={() => (active = i)} onclick={() => go(`/s/${results.scan}/hosts/${h.host_id}`)}><span class="mono">{h.display_name}</span><span class="meta muted mono">{h.ips.filter(Boolean).join(', ')}</span></button>{/each}
              {/if}
              {#if results.keys.length}
                <h3 class="micro muted">Keys</h3>
                {#each results.keys as k, j}{@const i = results.hosts.length + j}<button class="res" id={optId(i)} role="option" tabindex="-1" aria-selected={active === i} class:active={active === i} onmouseenter={() => (active = i)} onclick={() => go(keyHref(results.scan, k.fp))}><Fp fp={k.fp} copy={false} /><StrengthChip strength={k.strength} /><span class="meta secondary trunc">{k.label || k.comment || ''}</span></button>{/each}
              {/if}
              {#if results.users.length}
                <h3 class="micro muted">Users</h3>
                {#each results.users as u, j}{@const i = results.hosts.length + results.keys.length + j}<button class="res" id={optId(i)} role="option" tabindex="-1" aria-selected={active === i} class:active={active === i} onmouseenter={() => (active = i)} onclick={() => go(`/s/${results.scan}/hosts/${u.host_id}?tab=users#user-${encodeURIComponent(u.username)}`)}><span class="mono">{u.username} <span class="muted">@</span> {u.host}</span></button>{/each}
              {/if}
            {/if}
          </div>
        {/if}
      </div>

      <div class="spacer"></div>
      <div class="usermenu">
        <button class="btn ghost" aria-haspopup="menu" aria-expanded={userMenu} onclick={() => (userMenu = !userMenu)}>{session.username} <span aria-hidden="true">▾</span></button>
        {#if userMenu}
          <div class="popover um" role="menu">
            <div class="micro muted thl">Theme</div>
            <div class="seg" role="radiogroup" aria-label="Theme">
              {#each THEMES as [k, l]}<button role="radio" aria-checked={theme.pref === k} onclick={() => setTheme(k)}>{l}</button>{/each}
            </div>
            <button class="btn ghost lo" role="menuitem" onclick={logout}>Log out</button>
          </div>
        {/if}
      </div>
    </header>
    <main id="main" tabindex="-1">
      {@render children()}
    </main>
  </div>
</div>
<Toast />

<style>
  .skip { position: absolute; left: -999px; top: 0; z-index: 100; background: var(--bg-raised); padding: var(--s3); }
  .skip:focus { left: var(--s3); top: var(--s3); }
  .synth { position: sticky; top: 0; z-index: 40; height: 32px; display: flex; align-items: center; justify-content: center;
    background-color: var(--synthetic-bg); color: var(--synthetic-text); font-size: 13px; font-weight: 500;
    background-image: repeating-linear-gradient(45deg, var(--synthetic-hatch) 0 6px, transparent 6px 12px); }
  .synth span { background: var(--synthetic-bg); padding: 0 var(--s3); }
  .layout { display: flex; min-height: 100vh; }
  .layout.has-synth { min-height: calc(100vh - 32px); }
  .side { width: var(--sidebar); flex: none; background: var(--bg-surface); border-right: 1px solid var(--border-subtle);
    display: flex; flex-direction: column; position: sticky; top: 0; height: 100vh; overflow-y: auto; }
  .has-synth .side { top: 32px; height: calc(100vh - 32px); }
  .brand { height: 48px; display: flex; align-items: center; padding: 0 var(--s5); }
  .wordmark { font: 500 16px/22px var(--mono); letter-spacing: .02em; }
  .side ul { list-style: none; margin: var(--s3) 0; padding: 0; }
  .side a { display: flex; align-items: center; gap: var(--s4); height: 36px; padding: 0 var(--s5); color: var(--text-secondary);
    border-left: 3px solid transparent; transition: background var(--t-fast) ease-out; text-decoration: none; }
  .side a:hover { background: var(--bg-hover); color: var(--text-primary); }
  .side a.active { background: var(--accent-subtle); border-left-color: var(--accent); color: var(--accent); }
  .side a:focus-visible { outline-offset: -2px; }
  hr { border: 0; border-top: 1px solid var(--border-subtle); margin: var(--s2) var(--s5); }
  .foot { margin-top: auto; padding: var(--s5); }
  .main-col { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .top { height: 48px; display: flex; align-items: center; gap: var(--s4); padding: 0 var(--s6);
    border-bottom: 1px solid var(--border-subtle); background: var(--bg-surface); position: sticky; top: 0; z-index: 30; }
  .has-synth .top { top: 32px; }
  main { padding: var(--s6); max-width: 1920px; width: 100%; display: flex; flex-direction: column; gap: var(--s5); }
  main:focus { outline: none; }
  .menu-btn { display: none; }
  .scansel, .search, .usermenu { position: relative; }
  .sel { max-width: 460px; }
  .sel .trunc { max-width: 380px; }
  .menu { top: 36px; left: 0; min-width: 420px; max-height: 60vh; overflow: auto; list-style: none; margin: 0; padding: var(--s2) 0; }
  .menu button { all: unset; box-sizing: border-box; display: flex; align-items: center; gap: var(--s3); width: 100%; height: 32px;
    padding: 0 var(--s4); cursor: pointer; }
  .menu button:hover, .menu button:focus-visible { background: var(--bg-hover); }
  .menu button.selected { background: var(--bg-selected); }
  .menu .lbl2 { flex: 1; min-width: 0; }
  .st-running { background: var(--accent-subtle); color: var(--accent); }
  .st-failed, .st-aborted { background: var(--critical-bg); color: var(--critical); }
  .synchip { background: var(--accent-subtle); color: var(--accent); }
  .search { width: 320px; }
  .search .input { width: 100%; padding-right: var(--s7); }
  .kbd { position: absolute; right: var(--s3); top: 8px; border: 1px solid var(--border-strong); border-radius: var(--r1);
    padding: 0 var(--s2); color: var(--text-muted); }
  .results { top: 36px; left: 0; width: 420px; max-height: 70vh; overflow: auto; padding: var(--s3) 0; }
  .results h3 { padding: var(--s3) var(--s4) var(--s2); }
  .res { all: unset; box-sizing: border-box; display: flex; align-items: center; gap: var(--s3); width: 100%; min-height: 32px;
    padding: 0 var(--s4); cursor: pointer; font-size: 13px; }
  .res:hover, .res:focus-visible { background: var(--bg-hover); }
  .res.active { background: var(--bg-selected); box-shadow: inset 3px 0 0 var(--accent); }
  .none { padding: var(--s3) var(--s4); color: var(--text-secondary); }
  .um { right: 0; top: 36px; padding: var(--s3); display: flex; flex-direction: column; gap: var(--s3); min-width: 220px; }
  .thl { padding: 0 var(--s1); }
  .lo { justify-content: flex-start; }
  .scrim { display: none; }

  @media (max-width: 1279px) and (min-width: 1024px) {
    .side { width: 56px; }
    .side .lbl, .wordmark { display: none; }
    .brand::before { content: 'S'; font: 500 16px/22px var(--mono); }
    .side a { padding: 0; justify-content: center; }
    hr { margin: var(--s2) var(--s3); }
  }
  @media (max-width: 1023px) {
    .side { position: fixed; left: 0; top: 0; height: 100vh; z-index: 90; transform: translateX(-100%);
      transition: transform var(--t-mid) ease-out; }
    .side.open { transform: none; box-shadow: var(--e2); }
    .scrim { display: block; position: fixed; inset: 0; z-index: 85; }
    .menu-btn { display: inline-flex; }
    .top { padding: 0 var(--s3); gap: var(--s3); }
    .search { width: auto; flex: 1; min-width: 0; }
    .spacer { display: none; }
    .sel { max-width: 40vw; }
    .sel .trunc { max-width: 30vw; }
    .kbd { display: none; }
    main { padding: var(--s4); }
    .menu, .results { min-width: 0; width: min(420px, 92vw); }
  }
  @media (max-width: 600px) {
    .top { flex-wrap: wrap; height: auto; padding: var(--s2) var(--s3); }
    .search { order: 5; flex-basis: 100%; padding-bottom: var(--s2); }
    .synth { height: auto; min-height: 32px; text-align: center; padding: var(--s2); }
  }
</style>
