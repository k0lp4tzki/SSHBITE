<script lang="ts">
  // Tab bar that may be wider than its column (host detail at 375 px, check-12 F4): the bar scrolls sideways; an
  // edge that hides more tabs fades out and carries a chevron button that scrolls by most of a view. The selected
  // tab is scrolled into view whenever it changes.
  import type { Snippet } from 'svelte';
  import { tick } from 'svelte';
  let { children, selected = '', sticky = false }: { children: Snippet; selected?: string; sticky?: boolean } = $props();
  let bar: HTMLDivElement | undefined = $state();
  let moreLeft = $state(false), moreRight = $state(false);
  function measure() {
    if (!bar) return;
    moreLeft = bar.scrollLeft > 1;
    moreRight = bar.scrollLeft + bar.clientWidth < bar.scrollWidth - 1;
  }
  function by(dir: number) {
    if (!bar) return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    bar.scrollBy({ left: dir * Math.max(80, bar.clientWidth * 0.7), behavior: reduced ? 'auto' : 'smooth' });
  }
  $effect(() => {
    if (!bar) return;
    const ro = new ResizeObserver(measure);
    ro.observe(bar);
    measure();
    return () => ro.disconnect();
  });
  $effect(() => {
    selected;
    if (!bar) return;
    tick().then(() => {
      const t = bar?.querySelector<HTMLElement>('[role="tab"][aria-selected="true"]');
      if (!bar || !t) return;
      // keep the selected tab clear of the chevron buttons (32 px each side)
      const pad = 36, l = t.offsetLeft - bar.offsetLeft, r = l + t.offsetWidth;
      if (l - pad < bar.scrollLeft) bar.scrollLeft = Math.max(0, l - pad);
      else if (r + pad > bar.scrollLeft + bar.clientWidth) bar.scrollLeft = r + pad - bar.clientWidth;
      measure();
    });
  });
</script>

<div class="tabbar" class:sticky>
  <div class="tabs" role="tablist" bind:this={bar} onscroll={measure}>
    {@render children()}
  </div>
  {#if moreLeft}
    <span class="fade l" aria-hidden="true"></span>
    <button class="more l" tabindex="-1" aria-label="Scroll tabs left" onclick={() => by(-1)}>
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M10 3.5 5.5 8 10 12.5" fill="none" stroke="currentColor" stroke-width="1.5" /></svg>
    </button>
  {/if}
  {#if moreRight}
    <span class="fade r" aria-hidden="true"></span>
    <button class="more r" tabindex="-1" aria-label="Scroll tabs right" onclick={() => by(1)}>
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 3.5 10.5 8 6 12.5" fill="none" stroke="currentColor" stroke-width="1.5" /></svg>
    </button>
  {/if}
</div>

<style>
  .tabbar { position: relative; background: var(--bg-page); }
  .tabbar.sticky { position: sticky; top: var(--topbar); z-index: 5; }
  :global(.has-synth) .tabbar.sticky { top: calc(var(--topbar) + 32px); }
  .tabs { scrollbar-width: none; }
  .tabs::-webkit-scrollbar { display: none; }
  .fade { position: absolute; top: 0; bottom: 1px; width: 56px; pointer-events: none; }
  .fade.l { left: 0; background: linear-gradient(to right, var(--bg-page) 40%, transparent); }
  .fade.r { right: 0; background: linear-gradient(to left, var(--bg-page) 40%, transparent); }
  .more { position: absolute; top: 4px; width: 32px; height: 32px; display: grid; place-items: center; padding: 0;
    border: 0; border-radius: var(--r2); background: transparent; color: var(--text-secondary); cursor: pointer; }
  .more:hover { background: var(--bg-hover); color: var(--text-primary); }
  .more.l { left: 0; }
  .more.r { right: 0; }
</style>
