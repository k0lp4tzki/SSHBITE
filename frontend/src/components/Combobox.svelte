<script lang="ts">
  // Search-as-you-type combobox over /api/search (hosts or keys).
  import { api, qs } from '../lib/api';
  let { label, kind, scan, onpick }: { label: string; kind: 'hosts' | 'keys'; scan: number; onpick: (value: string, text: string) => void } = $props();
  let q = $state('');
  let items = $state<any[]>([]);
  let open = $state(false);
  let active = $state(0);
  let t: number | undefined;
  let root: HTMLElement;
  function input() {
    clearTimeout(t);
    if (q.trim().length < 1) { items = []; open = false; return; }
    t = window.setTimeout(async () => {
      try {
        const r = await api('/search' + qs({ q: q.trim(), scan }));
        items = kind === 'hosts' ? r.hosts.map((h: any) => ({ v: String(h.host_id), t: h.display_name, s: h.ips?.[0] ?? '' }))
          : r.keys.map((k: any) => ({ v: k.fp, t: k.fp.slice(0, 15) + '…', s: k.label || k.comment || '' }));
        active = 0;
        open = true;
      } catch { items = []; }
    }, 200);
  }
  function pick(i: any) { onpick(i.v, i.t); q = ''; items = []; open = false; }
  function key(e: KeyboardEvent) {
    if (!open) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); active = Math.min(items.length - 1, active + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); active = Math.max(0, active - 1); }
    else if (e.key === 'Enter' && items[active]) { e.preventDefault(); pick(items[active]); }
    else if (e.key === 'Escape') open = false;
  }
</script>

<svelte:window onclick={(e) => { if (open && !root.contains(e.target as Node)) open = false; }} />
<div class="cb" bind:this={root}>
  <input class="input" type="search" role="combobox" aria-expanded={open} aria-autocomplete="list" aria-label={label} placeholder={label}
    bind:value={q} oninput={input} onkeydown={key} />
  {#if open}
    <ul class="popover lst" role="listbox">
      {#each items as i, k}
        <li role="option" aria-selected={k === active}><button class:act={k === active} onclick={() => pick(i)}><span class:mono={kind === 'keys'} class="it">{i.t}</span><span class="meta secondary">{i.s}</span></button></li>
      {:else}<li class="none meta secondary">No match</li>{/each}
    </ul>
  {/if}
</div>

<style>
  .cb { position: relative; }
  .cb .input { width: 160px; }
  .lst { top: 36px; left: 0; min-width: 260px; list-style: none; margin: 0; padding: var(--s2) 0; max-height: 300px; overflow: auto; }
  .lst button { all: unset; box-sizing: border-box; display: flex; gap: var(--s3); align-items: center; width: 100%; height: 32px;
    padding: 0 var(--s4); cursor: pointer; }
  .lst button:hover, .lst button.act { background: var(--bg-hover); }
  .none { padding: var(--s3) var(--s4); }
  .it { font-size: 13px; }
</style>
