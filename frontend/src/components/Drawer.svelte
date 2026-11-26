<script lang="ts">
  // Right drawer, 520 px (design-revision §5.2): 56 px head with the title in type.title-sm and a 12 px subline,
  // a footer for actions. Esc closes, focus is trapped and returns to the trigger.
  import type { Snippet } from 'svelte';
  let { title, sub = '', onclose, children, footer = undefined }: { title: string; sub?: string; onclose: () => void; children: Snippet; footer?: Snippet } = $props();
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
  <header>
    <div class="ht"><h2 class="title-sm">{title}</h2>{#if sub}<p class="meta muted">{sub}</p>{/if}</div>
    <button class="btn ghost icon" onclick={onclose} aria-label="Close"><svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" /></svg></button>
  </header>
  <div class="content">{@render children()}</div>
  {#if footer}<footer>{@render footer()}</footer>{/if}
</aside>
<style>
  .scrim { position: fixed; inset: 0; z-index: 70; background: rgba(16, 24, 40, .16); }
  .drawer { position: fixed; top: 0; right: 0; bottom: 0; width: min(520px, 100vw); background: var(--bg-raised);
    box-shadow: var(--e2); border-left: 1px solid var(--raised-border); z-index: 71; display: flex; flex-direction: column; }
  header { display: flex; align-items: center; justify-content: space-between; gap: var(--s3); min-height: 56px;
    padding: var(--s3) var(--s4) var(--s3) var(--s6); border-bottom: 1px solid var(--border-subtle); }
  .ht { display: flex; flex-direction: column; min-width: 0; }
  .content { overflow: auto; padding: var(--s4) 0; flex: 1; }
  .content :global(.table-wrap) { --sticky-bg: var(--bg-raised); }
  .content :global(.table-wrap.sticky-first table.t > tbody > tr > td:first-child),
  .content :global(.table-wrap.sticky-first table.t > thead > tr > th:first-child) { box-shadow: none; }
  .content :global(table.t th:first-child), .content :global(table.t td:first-child) { padding-left: var(--s6); }
  .content :global(table.t th:last-child), .content :global(table.t td:last-child) { padding-right: var(--s6); }
  footer { display: flex; gap: var(--s3); padding: var(--s4) var(--s6); border-top: 1px solid var(--border-subtle); }
</style>
