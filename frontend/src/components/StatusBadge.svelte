<script lang="ts">
  import Glyph from './Glyph.svelte';
  import { STATUS_LABEL, statusGlyph, statusSev } from '../lib/format';
  let { status, label = '' }: { status: string; label?: string } = $props();
</script>

<span class="badge sev-{statusSev(status)}"><Glyph kind={statusGlyph(status)} />{label || STATUS_LABEL[status] || status}</span>
