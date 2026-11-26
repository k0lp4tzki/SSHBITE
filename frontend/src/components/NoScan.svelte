<script lang="ts">
  import CodeBlock from './CodeBlock.svelte';
</script>
<section class="empty-state">
  <h2>No scans yet</h2>
  <p>SSHBITE starts at your verified entry point and crawls from there. Run a scan from the command line:</p>
  <CodeBlock cmd="sshbite scan" />
  <p>If hosts need a sudo password: <span class="mono cmd">sshbite scan --ask-sudo-password</span></p>
  <p class="muted">This page updates as soon as a scan is running.</p>
</section>
<style>
  .cmd { font-size: 13px; color: var(--text-primary); }
</style>
