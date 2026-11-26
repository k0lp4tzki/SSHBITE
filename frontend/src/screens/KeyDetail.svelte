<script lang="ts">
  // Key detail (design §4.10): where the key is authorized, held, copied; its access and findings; the label form.
  import { api, fpFromUrl, fpUrl } from '../lib/api';
  import { route, setQuery } from '../lib/router.svelte';
  import { Resource } from '../lib/state.svelte';
  import { fileLine, fmtTime, midTrunc, utcTitle } from '../lib/format';
  import { graphKeyHref, hostHref } from '../lib/links';
  import PageHead from '../components/PageHead.svelte';
  import Notices from '../components/Notices.svelte';
  import StrengthChip from '../components/StrengthChip.svelte';
  import KeyType from '../components/KeyType.svelte';
  import Fp from '../components/Fp.svelte';
  import Glyph from '../components/Glyph.svelte';
  import OptionChips from '../components/OptionChips.svelte';
  import EdgeTable from '../components/EdgeTable.svelte';
  import FindingsTable from '../components/FindingsTable.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';
  import Skeleton from '../components/Skeleton.svelte';

  let { scan, fp: fpParam }: { scan: any; fp: string } = $props();
  const sid = scan.id;
  const fp = $derived(fpFromUrl(fpParam));
  const res = new Resource<any>();
  const load = () => res.load(() => api(`/scans/${sid}/keys/${fpUrl(fp)}`));
  $effect(() => { fp; load(); });
  const d = $derived(res.data);
  const tab = $derived(route.query.get('tab') ?? 'authorized');

  // label form
  let label = $state(''), owner = $state(''), note = $state('');
  let orig = $state({ label: '', owner: '', note: '' });
  let meta = $state<any>(null);
  let saving = $state(false), saved = $state(false), saveErr = $state('');
  $effect(() => {
    const l = d?.label ?? (res.errorCode === 'key_not_in_scan' ? null : undefined);
    if (l === undefined) return;
    orig = { label: l?.label ?? '', owner: l?.owner ?? '', note: l?.note ?? '' };
    label = orig.label; owner = orig.owner; note = orig.note;
    meta = l;
  });
  const dirty = $derived(label !== orig.label || owner !== orig.owner || note !== orig.note);
  let savedTimer: number | undefined;
  async function save(e: Event) {
    e.preventDefault();
    saving = true; saveErr = ''; saved = false;
    try {
      const r = await api(`/keys/${fpUrl(fp)}/label`, { method: 'PUT', body: { label, owner, note } });
      orig = { label: r.label ?? '', owner: r.owner ?? '', note: r.note ?? '' };
      label = orig.label; owner = orig.owner; note = orig.note;
      meta = r;
      saved = true;
      clearTimeout(savedTimer);
      savedTimer = window.setTimeout(() => (saved = false), 3000);
    } catch (err: any) {
      saveErr = err.message;
    } finally { saving = false; }
  }
  const effectiveAcc = $derived((d?.edges ?? []).filter((e: any) => e.kind === 'access'));
</script>

{#snippet labelForm()}
  <form class="panel lf" onsubmit={save}>
    <h2 class="section-title">Label</h2>
    <label class="field">Label<input class="input" maxlength="80" placeholder="e.g. contractor 2019 – remove" bind:value={label} /></label>
    <label class="field">Owner<input class="input" maxlength="80" placeholder="Person or team" bind:value={owner} /></label>
    <label class="field">Note<textarea class="input" rows="4" maxlength="2000" bind:value={note}></textarea>
      {#if note.length >= 1800}<span class="meta num secondary">{note.length}/2000</span>{/if}</label>
    <div class="row">
      <button class="btn primary" type="submit" disabled={!dirty || saving}>{saving ? 'Saving…' : 'Save label'}</button>
      {#if saved}<span class="ok sev-good" role="status"><span class="g"><Glyph kind="good" /></span>Saved</span>{/if}
    </div>
    {#if saveErr}<p class="err sev-critical" role="alert"><Glyph kind="critical" />Couldn't save: {saveErr}</p>{/if}
    <p class="meta muted">Stored only in this SSHBITE database. Kept when scans are deleted.</p>
    {#if meta?.updated_at}<p class="meta secondary" title={utcTitle(meta.updated_at)}>Updated {fmtTime(meta.updated_at)} by {meta.updated_by}</p>{/if}
  </form>
{/snippet}

{#if res.errorCode === 'key_not_in_scan'}
  <PageHead title="Key" />
  <div class="grid-2">
    <section class="empty-state"><h2 class="section-title">Key {fp.replace('SHA256:', 'SHA256:').slice(0, 11)}…{fp.slice(-4)} does not occur in scan #{sid}.</h2>
      <p class="secondary">It may have been removed before this scan, or it belongs to another scan. <a href="/scans">Show all scans</a></p></section>
    {@render labelForm()}
  </div>
{:else if res.error}
  <PageHead title="Key" />
  <ErrorPanel thing="the key" message={res.error} retry={load} />
{:else if !d}
  {#if res.slow}<Skeleton />{/if}
{:else}
  <header class="kh">
    <div class="r1">
      <h1 class="page-title"><Fp fp={d.fp} full /></h1>
      <StrengthChip strength={d.strength} /><KeyType alg={d.alg} bits={d.bits} />
      <span class="nowrap">origin: {#if d.origin === 'known'}Known{:else}<span class="sev-info unk"><Glyph kind="unknown" /></span> Unknown{/if}</span>
      <span class="spacer"></span>
      <a class="btn" href={graphKeyHref(sid, d.fp)}>Show in graph</a>
    </div>
    <p class="secondary"><span class="mono">{d.comments.join(', ') || 'no comment'}</span> · {d.label.label ? `“${d.label.label}”` : '(no label)'}{#if d.label.owner}{' · '}owner {d.label.owner}{/if}</p>
  </header>
  <Notices {scan} />
  <div class="grid-2">
    <div class="stack">
      <div class="tabs" role="tablist">
        {#each [['authorized', `Authorized on (${d.authorized_on.length})`], ['private', `Private half (${d.private_on.length})`], ['pub', `.pub copies (${d.pub_on.length})`], ['access', `Access (${effectiveAcc.length})`], ['findings', `Findings (${d.findings.length})`]] as [k, l]}
          <button role="tab" aria-selected={tab === k} onclick={() => setQuery({ tab: k === 'authorized' ? null : k }, true)}>{l}</button>
        {/each}
      </div>
      <section class="panel flush">
        {#if tab === 'authorized'}
          <div class="table-wrap"><table class="t">
            <thead><tr><th>Host</th><th>User</th><th>File:line</th><th>Options</th><th>Effective</th></tr></thead>
            <tbody>{#each d.authorized_on as a (a.id)}<tr>
              <td class="mono"><a href={hostHref(sid, a.host_id, 'users', `user-${a.username}`)}>{a.host}</a></td>
              <td class="mono">{a.username}</td>
              <td class="mono" title={fileLine(a.file, a.line)}>{midTrunc(fileLine(a.file, a.line), 40)}</td>
              <td>{#if a.cert_authority}<span class="kchip">CA trusted</span> {/if}<OptionChips options={a.options.filter((o: any) => o[0] !== 'cert-authority')} /></td>
              <td>{a.cert_authority ? '–' : a.effective === null || a.effective === undefined ? '–' : a.effective ? 'yes' : 'no'}</td>
            </tr>{:else}<tr><td class="empty" colspan="5">This key is not authorized on any scanned host.</td></tr>{/each}</tbody>
          </table></div>
        {:else if tab === 'private'}
          <div class="table-wrap"><table class="t">
            <thead><tr><th>Host</th><th>User</th><th>Path</th><th>Encrypted</th><th>Mode</th><th>Owner</th></tr></thead>
            <tbody>{#each d.private_on as p}<tr>
              <td class="mono"><a href={hostHref(sid, p.host_id, 'users', `user-${p.username}`)}>{p.host}</a></td><td class="mono">{p.username}</td>
              <td class="mono" title={p.path}>{midTrunc(p.path, 44)}</td>
              <td>{#if p.encrypted === 'no'}<span class="badge sev-medium"><Glyph kind="medium" />no</span>{:else}{p.encrypted}{/if}</td>
              <td class="mono">{#if p.mode_bad}<span class="badge sev-high"><Glyph kind="high" />{p.mode}</span>{:else}{p.mode ?? '–'}{/if}</td>
              <td class="mono">{p.owner ?? '–'}</td>
            </tr>{:else}<tr><td class="empty" colspan="6">No private half was found on any scanned host. Whoever holds it is outside the scanned estate.</td></tr>{/each}</tbody>
          </table></div>
        {:else if tab === 'pub'}
          <div class="table-wrap"><table class="t">
            <thead><tr><th>Host</th><th>User</th><th>Path</th><th>Comment</th></tr></thead>
            <tbody>{#each d.pub_on as p}<tr><td class="mono"><a href={hostHref(sid, p.host_id)}>{p.host}</a></td><td class="mono">{p.username}</td>
              <td class="mono" title={p.path}>{midTrunc(p.path, 44)}</td><td class="mono">{p.comment ?? '–'}</td></tr>
            {:else}<tr><td class="empty" colspan="4">No .pub copy of this key was found.</td></tr>{/each}</tbody>
          </table></div>
        {:else if tab === 'access'}
          <EdgeTable edges={effectiveAcc} scan={sid} empty="This key gives no access between scanned hosts." />
        {:else if tab === 'findings'}
          <FindingsTable items={d.findings} scan={sid} empty="No findings for this key in scan #{sid}." />
        {/if}
      </section>
    </div>
    {@render labelForm()}
  </div>
{/if}

<style>
  .kh { display: flex; flex-direction: column; gap: var(--s2); }
  .r1 { display: flex; flex-wrap: wrap; align-items: center; gap: var(--s4); }
  .r1 .page-title :global(.fp) { font-size: 20px; line-height: 28px; font-weight: 500; }
  .unk { color: var(--c); }
  .lf { display: flex; flex-direction: column; gap: var(--s4); }
  .ok { display: inline-flex; gap: var(--s2); align-items: center; color: var(--c); }
  .g { display: inline-flex; color: var(--c); }
  .err { color: var(--c); font-size: 12px; display: flex; gap: var(--s3); align-items: center; }
  .spacer { flex: 1; }
</style>
