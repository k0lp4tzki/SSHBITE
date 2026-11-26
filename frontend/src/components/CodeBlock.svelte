<script lang="ts">
  import CopyButton from './CopyButton.svelte';
  let { cmd }: { cmd: string } = $props();
</script>

<div class="code copy-host"><span class="wrap-any">{cmd}</span><CopyButton text={cmd} label="Copy command" /></div>
