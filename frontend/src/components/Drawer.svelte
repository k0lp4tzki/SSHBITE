<script lang="ts">
  // Right drawer, 480 px (design §6.2): Esc closes, focus is trapped and returns to the trigger.
  import type { Snippet } from 'svelte';
  let { title, onclose, children }: { title: string; onclose: () => void; children: Snippet } = $props();
  let el: HTMLElement;
  const trigger = document.activeElement as HTMLElement | null;

  $effect(() => {
    el?.querySelector<HTMLElement>('button, a, [tabindex]')?.focus();
    return () => trigger?.focus?.();
  });
  function key(e: KeyboardEvent) {
    if (e.key === 'Escape') { e.stopPropagation(); onclose(); }
    if (e.key === 'Tab') {
      const f = [...el.querySelectorAll<HTMLElement>('button, a[href], input, select, [tabindex]:not([tabindex="-1"])')];
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }
</script>

<div class="scrim" onclick={onclose} aria-hidden="true"></div>
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<aside class="drawer" role="dialog" aria-modal="true" aria-label={title} bind:this={el} onkeydown={key}>
  <header><h2 class="section-title mono">{title}</h2><button class="btn ghost icon" onclick={onclose} aria-label="Close">✕</button></header>
  <div class="content">{@render children()}</div>
</aside>

<style>
  .scrim { position: fixed; inset: 0; z-index: 70; }
  .drawer { position: fixed; top: 0; right: 0; bottom: 0; width: min(480px, 100vw); background: var(--bg-raised);
    box-shadow: var(--e2); border-left: 1px solid var(--raised-border); z-index: 71; display: flex; flex-direction: column; }
  header { display: flex; align-items: center; justify-content: space-between; padding: var(--s4) var(--s5);
    border-bottom: 1px solid var(--border-subtle); }
  .content { overflow: auto; padding: var(--s5) var(--s3); flex: 1; }
  .content :global(.table-wrap) { --sticky-bg: var(--bg-raised); }
</style>
