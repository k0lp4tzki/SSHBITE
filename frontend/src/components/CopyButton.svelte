<script lang="ts">
  // Copy button (design §6.1): icon -> check and "Copied" for 1.5 s; failure says how to copy by hand.
  let { text, label = 'Copy', visible = true }: { text: string; label?: string; visible?: boolean } = $props();
  let state = $state<'idle' | 'ok' | 'fail'>('idle');
  let timer: number | undefined;

  async function copy(e: MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        ok = true;
      }
    } catch { ok = false; }
    if (!ok) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.className = 'sr-only';
      document.body.appendChild(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch { ok = false; }
      ta.remove();
    }
    state = ok ? 'ok' : 'fail';
    clearTimeout(timer);
    timer = window.setTimeout(() => (state = 'idle'), ok ? 1500 : 4000);
  }
</script>

<button type="button" class="copy" class:shown={visible || state !== 'idle'} onclick={copy}
  title={state === 'fail' ? 'Copy failed – select and copy manually' : label} aria-label={state === 'ok' ? 'Copied' : label}>
  {#if state === 'ok'}
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><path d="M2.5 7.5 L5.5 10.5 L11.5 3.5" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>
    <span class="lbl">Copied</span>
  {:else}
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><rect x="4.5" y="4.5" width="7.5" height="7.5" rx="1" fill="none" stroke="currentColor" stroke-width="1.2"/><path d="M9.5 2 H3 a1 1 0 0 0 -1 1 V9.5" fill="none" stroke="currentColor" stroke-width="1.2"/></svg>
    {#if state === 'fail'}<span class="lbl fail">Copy failed – select and copy manually</span>{/if}
  {/if}
</button>

<style>
  .copy { display: inline-flex; align-items: center; gap: var(--s2); min-width: 24px; height: 24px; padding: 0 var(--s1);
    justify-content: center; border: 0; border-radius: var(--r2); background: transparent; color: var(--text-secondary);
    cursor: pointer; opacity: 0; transition: background var(--t-fast) ease-out; vertical-align: middle; flex: none; }
  .copy.shown, .copy:focus-visible { opacity: 1; }
  .copy:hover { background: var(--bg-hover); }
  .lbl { font: 500 11px/14px var(--sans); }
  .fail { color: var(--critical); }
  :global(.fp-host:hover) .copy, :global(tr:hover) .copy, :global(.copy-host:hover) .copy { opacity: 1; }
</style>
