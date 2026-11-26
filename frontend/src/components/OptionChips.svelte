<script lang="ts">
  // authorized_keys options as chips (design §6.2): from= truncated at 40 chars, command= outlined.
  let { options, expiry = null }: { options: [string, string | null][]; expiry?: string | null } = $props();
  function text(name: string, value: string | null) {
    if (name === 'expiry-time') return `expiry ${value}`;
    if (value === null || value === undefined) return name;
    return `${name}="${value}"`;
  }
  const trunc = (s: string) => (s.length > 40 ? s.slice(0, 39) + '…' : s);
</script>

{#if options.length === 0}
  <span class="muted">–</span>
{:else}
  <span class="chips">
    {#each options as [name, value]}
      <span class="kchip" class:outline={name === 'command'} title={text(name, value)}>{trunc(text(name, value))}</span>
    {/each}
  </span>
{/if}
