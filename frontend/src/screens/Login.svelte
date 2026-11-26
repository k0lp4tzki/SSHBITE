<script lang="ts">
  import { api, ApiError } from '../lib/api';
  import { route } from '../lib/router.svelte';
  import Glyph from '../components/Glyph.svelte';

  let { onlogin }: { onlogin: (next: string) => void } = $props();
  let username = $state('');
  let password = $state('');
  let busy = $state(false);
  let error = $state('');
  let pwEl: HTMLInputElement;
  const expired = $derived(route.query.get('expired') === '1');

  function lockText(until: string | undefined): string {
    if (!until) return 'This account is locked after 5 failed attempts. Try again in 15 minutes.';
    const mins = Math.max(1, Math.ceil((new Date(until).getTime() - Date.now()) / 60000));
    return `This account is locked after 5 failed attempts. Try again in ${mins} minute${mins === 1 ? '' : 's'}.`;
  }

  async function submit(e: Event) {
    e.preventDefault();
    if (busy) return;
    busy = true;
    error = '';
    try {
      await api('/login', { method: 'POST', body: { username, password }, noRedirect: true });
      onlogin(route.query.get('next') ?? '/');
    } catch (err) {
      const x = err as ApiError;
      if (x.status === 429) error = 'Too many attempts from this address. Wait 15 minutes and try again.';
      else if (x.code === 'account_locked') error = lockText(x.body?.locked_until);
      else if (x.status === 401) error = 'Wrong username or password.';
      else if (x.status === 0) error = "Can't reach the SSHBITE server.";
      else error = x.message;
      password = '';
      pwEl?.focus();
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  <form class="card" onsubmit={submit} novalidate>
    <div>
      <div class="wordmark">SSHBITE</div>
      <div class="secondary">SSH access audit</div>
    </div>
    {#if expired}<div class="strip info" role="status">Your session has ended. Log in again.</div>{/if}
    <label class="field">Username
      <!-- svelte-ignore a11y_autofocus -->
      <input class="input" name="username" autocomplete="username" autofocus bind:value={username} required />
    </label>
    <label class="field">Password
      <input class="input" class:error={!!error} name="password" type="password" autocomplete="current-password" bind:this={pwEl} bind:value={password} required />
    </label>
    <button class="btn primary" type="submit" disabled={busy}>{busy ? 'Logging in…' : 'Log in'}</button>
    {#if error}<p class="err sev-critical" role="alert"><Glyph kind="critical" /><span>{error}</span></p>{/if}
  </form>
  <p class="foot meta muted">Read-only audit tool. Data stays on this machine.</p>
</div>

<style>
  .wrap { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: var(--s5);
    background: var(--bg-page); padding: var(--s5); }
  .card { width: min(360px, 100%); background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--r3);
    padding: var(--s6); display: flex; flex-direction: column; gap: var(--s5); }
  .wordmark { font: 500 16px/22px var(--mono); }
  .btn { width: 100%; }
  .err { color: var(--c); font-size: 12px; line-height: 16px; display: flex; gap: var(--s3); align-items: flex-start; }
  .err :global(.glyph) { margin-top: 2px; }
</style>
