<script lang="ts">
  import { api, ApiError } from '../lib/api';
  import { route } from '../lib/router.svelte';
  import Strip from '../components/Strip.svelte';

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
    <div class="brand">
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
        <rect x="0" y="0" width="7" height="7" fill="var(--border-default)" /><rect x="9" y="0" width="7" height="7" fill="var(--accent)" />
        <rect x="0" y="9" width="7" height="7" fill="var(--border-default)" /><rect x="9" y="9" width="7" height="7" fill="var(--border-default)" />
      </svg>
      <span class="wordmark">SSHBITE</span>
    </div>
    <div class="head">
      <h1 class="title-sm">Log in</h1>
      <p class="secondary sub">SSH access audit</p>
    </div>
    {#if expired}<Strip role="info">Your session has ended. Log in again.</Strip>{/if}
    {#if error}<div class="err"><Strip role="error">{error}</Strip></div>{/if}
    <label class="field">Username
      <!-- svelte-ignore a11y_autofocus -->
      <input class="input" name="username" autocomplete="username" autofocus bind:value={username} required />
    </label>
    <label class="field">Password
      <input class="input" class:error={!!error} name="password" type="password" autocomplete="current-password" bind:this={pwEl} bind:value={password} required />
    </label>
    <button class="btn primary" type="submit" disabled={busy}>{busy ? 'Logging in…' : 'Log in'}</button>
  </form>
  <p class="foot">Read-only audit tool. Data stays on this machine.</p>
</div>

<style>
  /* login (design-revision §5.7): 400 px card on bg.page, top edge at 30 % of the window height */
  .wrap { min-height: 100vh; display: flex; flex-direction: column; align-items: center; background: var(--bg-page);
    padding: 30vh var(--s5) var(--s5); }
  .card { width: min(400px, 100%); background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: var(--r4);
    padding: var(--s7); display: flex; flex-direction: column; gap: var(--s5); }
  .brand { display: flex; align-items: center; gap: var(--s3); }
  .wordmark { font: 600 16px/24px var(--sans); }
  .head { display: flex; flex-direction: column; gap: var(--s1); }
  .sub { font-size: 13px; line-height: 20px; }
  .field .input { width: 100%; }
  .btn { width: 100%; height: 36px; }
  .err :global(.strip) { padding: var(--s3) var(--s4); }
  .foot { margin-top: var(--s5); font-size: 12px; line-height: 16px; color: var(--text-muted); text-align: center; }
  @media (max-height: 760px) { .wrap { padding-top: 12vh; } }
</style>
