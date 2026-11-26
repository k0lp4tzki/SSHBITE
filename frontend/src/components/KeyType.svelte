<script lang="ts">
  import { isCert, keyType } from '../lib/format';
  let { alg, bits = null }: { alg: string | null | undefined; bits?: number | null } = $props();
</script>

<span class="chips"><span class="kchip">{keyType(alg, bits)}</span>{#if isCert(alg)}<span class="kchip">cert</span>{/if}</span>
