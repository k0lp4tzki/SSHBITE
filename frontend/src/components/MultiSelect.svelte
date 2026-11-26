<script lang="ts">
  // A select with checkboxes; shows "{label}: all" or the chosen values.
  let { label, options, value, onchange, allLabel = 'all' }:
    { label: string; options: { value: string; label: string; count?: number }[]; value: string[]; onchange: (v: string[]) => void; allLabel?: string } = $props();
  let open = $state(false);
  let root: HTMLElement;
  const text = $derived(value.length === 0 ? allLabel : value.length <= 2 ? value.map((v) => options.find((o) => o.value === v)?.label ?? v).join(', ') : `${value.length} selected`);
  function toggle(v: string) {
    onchange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]);
  }
</script>

<svelte:window onclick={(e) => { if (open && !root.contains(e.target as Node)) open = false; }} onkeydown={(e) => { if (e.key === 'Escape') open = false; }} />
<div class="ms" bind:this={root}>
  <button class="select btnsel" aria-haspopup="listbox" aria-expanded={open} onclick={() => (open = !open)}>{label}: {text}</button>
  {#if open}
    <div class="popover list" role="listbox" aria-multiselectable="true" aria-label={label}>
      {#each options as o}
        <label class="check opt" role="option" aria-selected={value.includes(o.value)}>
          <input type="checkbox" checked={value.includes(o.value)} onchange={() => toggle(o.value)} />
          <span class="ol">{o.label}</span>{#if o.count !== undefined}<span class="num muted meta">{o.count}</span>{/if}
        </label>
      {/each}
      {#if value.length}<button class="btn ghost small clr" onclick={() => onchange([])}>Clear</button>{/if}
    </div>
  {/if}
</div>

<style>
  .ms { position: relative; }
  .btnsel { text-align: left; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .list { top: 36px; left: 0; min-width: 220px; max-height: 360px; overflow: auto; padding: var(--s2) 0; }
  .opt { display: flex; padding: 0 var(--s4); height: 32px; width: 100%; }
  .opt:hover { background: var(--bg-hover); }
  .ol { flex: 1; white-space: nowrap; }
  .clr { margin: var(--s2) var(--s4); }
</style>
