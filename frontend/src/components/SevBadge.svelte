<script lang="ts">
  import Badge from './Badge.svelte';
  import { SEV_LABEL } from '../lib/format';
  let { severity, count = null, compact = false }: { severity: string; count?: number | null; compact?: boolean } = $props();
</script>
<Badge role={severity} label={SEV_LABEL[severity] ?? severity} {count} {compact} />
