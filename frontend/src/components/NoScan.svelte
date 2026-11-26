<script lang="ts">
  import CodeBlock from './CodeBlock.svelte';
</script>

<section class="empty-state">
  <h2 class="section-title">No scans yet</h2>
  <p>SSHBITE starts at your verified entry point and crawls from there. Run a scan from the command line:</p>
  <CodeBlock cmd="sshbite scan" />
  <p class="mono dense">If hosts need a sudo password: sshbite scan --ask-sudo-password</p>
  <p class="muted">This page updates as soon as a scan is running.</p>
</section>
