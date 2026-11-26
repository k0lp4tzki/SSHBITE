<script lang="ts">
  // Host status (design-revision §3.2): OK as text, Partial Medium, unreachable family High, host key Critical,
  // not scanned as muted text.
  import Badge from './Badge.svelte';
  import { STATUS_LABEL, statusSev } from '../lib/format';
  let { status, label = '' }: { status: string; label?: string } = $props();
  const sev = $derived(statusSev(status));
  const text = $derived(label || STATUS_LABEL[status] || status);
</script>
{#if status === 'ok'}<span class="state">{text}</span>
{:else if sev === 'info'}<span class="state muted">{text}</span>
{:else}<Badge role={sev} label={text} />{/if}
