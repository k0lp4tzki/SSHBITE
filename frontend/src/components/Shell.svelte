<script lang="ts">
  // App shell (design-revision §4): synthetic banner, 232 px sidebar in three groups, 56 px top bar with the
  // two-line scan context (on /diff: "Comparing scan #a with scan #b"), search with the "/" hint, user menu.
  import type { Snippet } from 'svelte';
  import { api, qs } from '../lib/api';
  import { navigate, route } from '../lib/router.svelte';
  import { live, scans, session, setTheme, theme, type ThemePref } from '../lib/state.svelte';
  import { fmtTime, n, STATUS_LABEL, statusSev, utcTitle } from '../lib/format';
  import { keyHref } from '../lib/links';
  import StrengthChip from './StrengthChip.svelte';
  import Badge from './Badge.svelte';
  import Fp from './Fp.svelte';
  import Toast from './Toast.svelte';

  let { scanId = null, synthetic = false, compare = null, children }:
    { scanId?: number | null; synthetic?: boolean; compare?: [number, number] | null; children: Snippet } = $props();

  const current = $derived(scans.items.find((s) => s.id === scanId) ?? null);
  const navScan = $derived(scanId ?? scans.items.find((s) => s.status === 'completed')?.id ?? scans.items[0]?.id ?? null);

  // three groups without headings (revision §4 Seitenleiste); icons 16 px, 1.5 line
  const GROUPS: { key?: string; href?: string; label: string; icon: string }[][] = [
    [
      { key: '', label: 'Dashboard', icon: 'M2.5 2.5h4.5v5H2.5zM9 2.5h4.5v3H9zM9 7.5h4.5v6H9zM2.5 9.5h4.5v4H2.5z' },
      { key: 'heatmap', label: 'Heatmap', icon: 'M2.5 2.5h3v3h-3zM6.5 2.5h3v3h-3zM10.5 2.5h3v3h-3zM2.5 6.5h3v3h-3zM6.5 6.5h3v3h-3zM2.5 10.5h3v3h-3z' },
      { key: 'graph', label: 'Graph', icon: 'M5.5 4.5l5 1.5M4.5 5.5l1 5M11 7.5l-4 4M2.5 2.5h3v3h-3zM10.5 4.5h3v3h-3zM4.5 10.5h3v3h-3z' },
      { key: 'crawl', label: 'Crawl tree', icon: 'M3.5 2.5v9.5h3M3.5 7h3M6.5 5.5h7v3h-7zM6.5 10.5h7v3h-7z' },
    ],
    [
      { key: 'hosts', label: 'Hosts', icon: 'M2.5 3h11v4h-11zM2.5 9h11v4h-11zM5 5h.5M5 11h.5' },
      { key: 'keys', label: 'Keys', icon: 'M8.5 8a3 3 0 1 1-6 0 3 3 0 0 1 6 0zM8.5 8h5M11.5 8v2.5M13.5 8v2' },
      { key: 'findings', label: 'Findings', icon: 'M8 2.5l5.75 10.5H2.25zM8 6.5v3M8 11.2v.3' },
    ],
    [
      { href: '/scans', label: 'Scans', icon: 'M3 3.5h10M3 6.5h10M3 9.5h10M3 12.5h6' },
      { href: '/diff', label: 'Diff', icon: 'M5 2.5v11M11 2.5v11M2.5 5h5M8.5 11h5' },
    ],
  ];
  function navHref(key: string) {
    if (navScan === null) return '/';
    return `/s/${navScan}/${key}`;
  }
  function isActive(it: { key?: string; href?: string }) {
    if (it.href) return route.path.startsWith(it.href);
    const m = route.path.match(/^\/s\/\d+\/?([a-z]*)/);
    if (!m) return route.path === '/' && it.key === '';
    return (m[1] || '') === it.key;
  }
  const hrefOf = (it: { key?: string; href?: string }) => it.href ?? navHref(it.key ?? '');
  const runningProg = $derived(current && current.status === 'running' && live.scan?.id === current.id ? live.scan.progress : null);

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
  <div class="side-col" class:open={navOpen}>
    <nav class="side" aria-label="Main">
      <div class="brand">
        <svg class="mark" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
          <rect x="0" y="0" width="7" height="7" fill="var(--border-default)" /><rect x="9" y="0" width="7" height="7" fill="var(--accent)" />
          <rect x="0" y="9" width="7" height="7" fill="var(--border-default)" /><rect x="9" y="9" width="7" height="7" fill="var(--border-default)" />
        </svg>
        <span class="wordmark">SSHBITE</span>
      </div>
      {#each GROUPS as group, gi}
        {#if gi > 0}<hr />{/if}
        <ul>
          {#each group as it}
            {@const on = isActive(it)}
            <li><a href={hrefOf(it)} class:active={on} aria-current={on ? 'page' : undefined} title={it.label} onclick={() => (navOpen = false)}>
              <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d={it.icon} fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" /></svg>
              <span class="lbl">{it.label}</span></a></li>
          {/each}
        </ul>
      {/each}
      <div class="foot"><span class="lbl">Read-only audit</span><span class="lbl">v{session.version}</span></div>
    </nav>
  </div>
  {#if navOpen}<div class="scrim" onclick={() => (navOpen = false)} aria-hidden="true"></div>{/if}

  <div class="main-col">
    <header class="top">
      <button class="btn ghost icon menu-btn" aria-label="Menu" aria-expanded={navOpen} onclick={(e) => { e.stopPropagation(); navOpen = !navOpen; }}>
        <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M2.5 4h11M2.5 8h11M2.5 12h11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" /></svg>
      </button>
      {#if compare}
        <div class="ctxt compare"><span class="l1">Comparing scan #{compare[0]} with scan #{compare[1]}</span></div>
      {:else}
        <div class="scansel">
          <button class="sel" aria-haspopup="listbox" aria-expanded={scanMenu} onclick={() => (scanMenu = !scanMenu)} disabled={scans.items.length === 0}
            title={current ? utcTitle(current.started_at) : ''}>
            {#if current}
              <span class="ctxt">
                <span class="l1"><span class="sid">Scan #{current.id}</span><span class="slabel trunc">{current.label || 'unlabelled'}</span>
                  {#if current.synthetic}<span class="chip">Synthetic</span>{/if}</span>
                <span class="l2">
                  {#if current.status === 'running'}<span class="run">Running – depth {runningProg?.depth ?? 0}, {n(runningProg?.queued ?? 0)} queued</span>
                  {:else if current.status === 'failed' || current.status === 'aborted'}<Badge role="critical" label={current.status === 'failed' ? 'Failed' : 'Aborted'} />
                  {:else}Completed {fmtTime(current.finished_at ?? current.started_at)}{/if}
                </span>
              </span>
            {:else if scans.items.length === 0}<span class="muted">No scans yet</span>{:else}<span>Choose a scan</span>{/if}
            <svg class="chev" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M3 4.5 6 7.5 9 4.5" fill="none" stroke="currentColor" stroke-width="1.5" /></svg>
          </button>
          {#if scanMenu}
            <ul class="popover menu" role="listbox" aria-label="Scans">
              {#each scans.items as s (s.id)}
                <li><button role="option" aria-selected={s.id === scanId} class:selected={s.id === scanId} onclick={() => pickScan(s.id)}>
                  <span class="num sid">#{s.id}</span>
                  <span class="trunc lbl2">{s.label || 'unlabelled'}</span>
                  {#if s.synthetic}<span class="chip">Synthetic</span>{/if}
                  {#if s.status === 'running'}<span class="run meta">Running</span>{:else if s.status !== 'completed'}<Badge role="critical" label={s.status === 'failed' ? 'Failed' : 'Aborted'} />{/if}
                  <span class="meta secondary nowrap num" title={utcTitle(s.started_at)}>{fmtTime(s.started_at)}</span>
                </button></li>
              {/each}
            </ul>
          {/if}
        </div>
      {/if}

      <div class="search" role="search">
        <svg class="lens" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="4.25" fill="none" stroke="currentColor" stroke-width="1.5" /><path d="M10.2 10.2 13.5 13.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" /></svg>
        <input bind:this={searchEl} class="input" type="search" placeholder="Search hosts, keys, users" aria-label="Search hosts, keys, users"
          role="combobox" aria-autocomplete="list" aria-controls="search-results" aria-expanded={searchOpen && !!results}
          aria-activedescendant={searchOpen && active >= 0 ? optId(active) : undefined}
          bind:value={q} oninput={onSearch} onkeydown={searchKey} onfocus={() => { if (results) searchOpen = true; }} />
        <kbd class="kbd" aria-hidden="true">/</kbd>
        {#if searchOpen && results}
          <div class="popover results" id="search-results" role="listbox" aria-label="Search results">
            {#if !results.hosts.length && !results.keys.length && !results.users.length}
              <p class="none">Nothing matches "{q}" in scan #{results.scan}.</p>
            {:else}
              {#if results.hosts.length}
                <h3 class="sec">Hosts</h3>
                {#each results.hosts as h, i}<button class="res" id={optId(i)} role="option" tabindex="-1" aria-selected={active === i} class:active={active === i} onmouseenter={() => (active = i)} onclick={() => go(`/s/${results.scan}/hosts/${h.host_id}`)}>
                  <span class="two"><span class="t1">{h.display_name}</span><span class="t2 num">{h.ips.filter(Boolean).join(', ') || '–'}</span></span>
                  {#if h.status && statusSev(h.status) !== 'low' && statusSev(h.status) !== 'info'}<Badge role={statusSev(h.status)} label={STATUS_LABEL[h.status] ?? h.status} />{/if}
                </button>{/each}
              {/if}
              {#if results.keys.length}
                <h3 class="sec">Keys</h3>
                {#each results.keys as k, j}{@const i = results.hosts.length + j}<button class="res" id={optId(i)} role="option" tabindex="-1" aria-selected={active === i} class:active={active === i} onmouseenter={() => (active = i)} onclick={() => go(keyHref(results.scan, k.fp))}>
                  <span class="two"><span class="t1"><Fp fp={k.fp} copy={false} /></span><span class="t2">{k.label || k.comment || 'no comment'}</span></span>
                  <StrengthChip strength={k.strength} />
                </button>{/each}
              {/if}
              {#if results.users.length}
                <h3 class="sec">Users</h3>
                {#each results.users as u, j}{@const i = results.hosts.length + results.keys.length + j}<button class="res" id={optId(i)} role="option" tabindex="-1" aria-selected={active === i} class:active={active === i} onmouseenter={() => (active = i)} onclick={() => go(`/s/${results.scan}/hosts/${u.host_id}?tab=users#user-${encodeURIComponent(u.username)}`)}>
                  <span class="two"><span class="t1">{u.username}</span><span class="t2">on {u.host}</span></span>
                </button>{/each}
              {/if}
            {/if}
          </div>
        {/if}
      </div>

      <div class="spacer"></div>
      <div class="usermenu">
        <button class="btn ghost um-btn" aria-haspopup="menu" aria-expanded={userMenu} onclick={() => (userMenu = !userMenu)}>{session.username}
          <svg class="chev" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M3 4.5 6 7.5 9 4.5" fill="none" stroke="currentColor" stroke-width="1.5" /></svg></button>
        {#if userMenu}
          <div class="popover um" role="menu">
            <div class="thl">Theme</div>
            <div class="seg" role="radiogroup" aria-label="Theme">
              {#each THEMES as [k, l]}<button role="radio" aria-checked={theme.pref === k} onclick={() => setTheme(k)}>{l}</button>{/each}
            </div>
            <hr />
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
  /* synthetic banner (revision §4): fully inverted, 32 px, not dismissable */
  .synth { position: sticky; top: 0; z-index: 40; height: 32px; display: flex; align-items: center; justify-content: center;
    gap: .3em; background: var(--synthetic-bg); color: var(--synthetic-text); font-size: 13px; line-height: 20px; font-weight: 500; }
  .synth .mono { font-weight: 400; }
  /* grid 232px 1fr: the sidebar background lies on the grid column, its content is sticky - so the background
     reaches the bottom on long pages (revision §4 Grundgerüst) */
  .layout { display: grid; grid-template-columns: var(--sidebar) minmax(0, 1fr); min-height: 100vh; }
  .layout.has-synth { min-height: calc(100vh - 32px); }
  .side-col { background: var(--bg-page); border-right: 1px solid var(--border-subtle); min-width: 0; }
  .side { position: sticky; top: 0; height: 100vh; overflow-y: auto; display: flex; flex-direction: column; }
  .has-synth .side { top: 32px; height: calc(100vh - 32px); }
  .brand { height: 56px; flex: none; display: flex; align-items: center; gap: var(--s3); padding: 0 var(--s5); }
  .mark { flex: none; }
  .wordmark { font: 600 16px/24px var(--sans); color: var(--text-primary); }
  .side ul { list-style: none; margin: 0; padding: var(--s2) 0; }
  .side a { display: flex; align-items: center; gap: var(--s4); height: 36px; margin: 0 var(--s3); padding: 0 var(--s3);
    border-radius: var(--r1); color: var(--text-secondary); font-size: 14px; font-weight: 500;
    transition: background var(--t-fast) ease-out; text-decoration: none; }
  .side a svg { flex: none; }
  .side a:hover { background: var(--bg-hover); color: var(--text-primary); }
  .side a.active { background: var(--bg-selected); color: var(--accent); }
  .side a:focus-visible { outline-offset: -2px; }
  hr { border: 0; border-top: 1px solid var(--border-subtle); margin: var(--s3) var(--s5); }
  .foot { margin-top: auto; padding: var(--s5); display: flex; flex-direction: column; font-size: 12px; line-height: 16px;
    color: var(--text-muted); }
  .main-col { min-width: 0; display: flex; flex-direction: column; }
  .top { height: var(--topbar); display: flex; align-items: center; gap: var(--s5); padding: 0 var(--s6);
    border-bottom: 1px solid var(--border-subtle); background: var(--bg-surface); position: sticky; top: 0; z-index: 30; }
  .has-synth .top { top: 32px; }
  main { padding: var(--s6); max-width: 1920px; width: 100%; display: flex; flex-direction: column; gap: var(--s5); }
  main:focus { outline: none; }
  .menu-btn { display: none; }
  .scansel, .search, .usermenu { position: relative; }
  /* scan context: menu button 40 px, no border */
  .sel { all: unset; box-sizing: border-box; display: inline-flex; align-items: center; gap: var(--s3); height: 40px;
    padding: 0 var(--s3); margin-left: calc(-1 * var(--s3)); border-radius: var(--r1); cursor: pointer; max-width: 420px; }
  .sel:hover { background: var(--bg-hover); }
  .sel:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .sel:disabled { cursor: default; }
  .ctxt { display: flex; flex-direction: column; min-width: 0; }
  .l1 { display: flex; align-items: center; gap: var(--s3); font-size: 14px; line-height: 20px; min-width: 0; white-space: nowrap; }
  .sid { font-weight: 600; }
  .slabel { color: var(--text-secondary); max-width: 220px; }
  .l2 { font-size: 12px; line-height: 16px; color: var(--text-muted); white-space: nowrap; }
  .run { color: var(--accent); }
  .compare .l1 { font-weight: 600; }
  .chev { flex: none; color: var(--text-muted); }
  .menu { top: 44px; left: -8px; min-width: 440px; max-height: 60vh; overflow: auto; list-style: none; margin: 0; padding: var(--s2) 0; }
  .menu button { all: unset; box-sizing: border-box; display: flex; align-items: center; gap: var(--s3); width: 100%; height: 36px;
    padding: 0 var(--s4); cursor: pointer; font-size: 14px; }
  .menu button:hover, .menu button:focus-visible { background: var(--bg-hover); }
  .menu button.selected { background: var(--bg-selected); }
  .menu .sid { width: 32px; }
  .menu .lbl2 { flex: 1; min-width: 0; }
  .search { width: 360px; flex: none; }
  .lens { position: absolute; left: 10px; top: 8px; color: var(--text-muted); pointer-events: none; }
  .search .input { width: 100%; padding-left: 34px; padding-right: 36px; }
  .kbd { position: absolute; right: 6px; top: 6px; width: 20px; height: 20px; display: grid; place-items: center;
    background: var(--bg-subtle); border: 1px solid var(--border-subtle); border-radius: var(--r1); color: var(--text-muted);
    font: 500 12px/16px var(--sans); }
  .results { top: 40px; left: 0; width: 440px; max-height: 70vh; overflow: auto; padding: var(--s2) 0; }
  .sec { padding: var(--s3) var(--s4) var(--s2); font-size: 12px; line-height: 16px; font-weight: 500; color: var(--text-muted); }
  .res { all: unset; box-sizing: border-box; display: flex; align-items: center; justify-content: space-between; gap: var(--s3);
    width: 100%; min-height: 48px; padding: var(--s2) var(--s4); cursor: pointer; }
  .res:hover, .res:focus-visible { background: var(--bg-hover); }
  .res.active { background: var(--bg-selected); }
  .two { display: flex; flex-direction: column; min-width: 0; }
  .t1 { font-size: 14px; line-height: 20px; font-weight: 500; color: var(--text-primary); }
  .t2 { font-size: 12px; line-height: 16px; color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .none { padding: var(--s3) var(--s4); color: var(--text-secondary); font-size: 14px; }
  .um-btn { font-weight: 500; color: var(--text-primary); }
  .um { right: 0; top: 40px; padding: var(--s3); display: flex; flex-direction: column; gap: var(--s3); min-width: 232px; }
  .um hr { margin: 0 calc(-1 * var(--s3)); }
  .thl { font-size: 12px; line-height: 16px; color: var(--text-muted); padding: 0 var(--s1); }
  .lo { justify-content: flex-start; }
  .scrim { display: none; }

  /* 1024-1279 px: icon rail 56 px */
  @media (max-width: 1279px) and (min-width: 1024px) {
    .layout { grid-template-columns: 56px minmax(0, 1fr); }
    .side .lbl, .wordmark { display: none; }
    .brand { justify-content: center; padding: 0; }
    .side a { padding: 0; margin: 0 var(--s3); justify-content: center; }
    hr { margin: var(--s3) var(--s3); }
    .foot { display: none; }
    .search { width: 300px; }
  }
  /* below 1024 px: overlay (as v1) */
  @media (max-width: 1023px) {
    .layout { grid-template-columns: minmax(0, 1fr); }
    .side-col { position: fixed; left: 0; top: 0; bottom: 0; width: var(--sidebar); z-index: 90; transform: translateX(-100%);
      transition: transform var(--t-mid) ease-out; }
    .side-col.open { transform: none; box-shadow: 8px 0 24px rgba(16, 24, 40, .12); }
    .side, .has-synth .side { top: 0; height: 100vh; }
    .scrim { display: block; position: fixed; inset: 0; z-index: 85; }
    .menu-btn { display: inline-flex; }
    .top { padding: 0 var(--s3); gap: var(--s3); }
    .search { width: auto; flex: 1; min-width: 0; }
    .spacer { display: none; }
    .sel { max-width: 44vw; margin-left: 0; }
    .slabel { max-width: 18vw; }
    .kbd { display: none; }
    main { padding: var(--s4); }
    .menu, .results { min-width: 0; width: min(440px, 92vw); }
  }
  @media (max-width: 600px) {
    .top { flex-wrap: wrap; height: auto; padding: var(--s2) var(--s3); row-gap: var(--s2); }
    .search { order: 5; flex-basis: 100%; padding-bottom: var(--s2); }
    .synth { height: auto; min-height: 32px; text-align: center; padding: var(--s2); flex-wrap: wrap; }
    .slabel { max-width: 30vw; }
  }
</style>
