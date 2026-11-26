<script lang="ts">
  // Heatmap (design §4.5 / §5): canvas matrix with sticky axis labels, margin bars, hover tooltip with the top
  // pairs, drill-down to host x host, edge drawer, ranking panel, table view, keyboard grid.
  import { onDestroy, tick } from 'svelte';
  import { scaleLinear } from 'd3-scale';
  import { api, qs } from '../lib/api';
  import { navigate, route, setQuery } from '../lib/router.svelte';
  import { Resource, theme } from '../lib/state.svelte';
  import { n, plural } from '../lib/format';
  import { BINS, commonSuffix, fitText, hatch, palette, setupCanvas, step, type Palette } from '../lib/heat';
  import { hostHref, keyHref } from '../lib/links';
  import PageHead from '../components/PageHead.svelte';
  import Notices from '../components/Notices.svelte';
  import Drawer from '../components/Drawer.svelte';
  import EdgeTable from '../components/EdgeTable.svelte';
  import Glyph from '../components/Glyph.svelte';
  import ErrorPanel from '../components/ErrorPanel.svelte';

  let { scan }: { scan: any } = $props();
  const sid = scan.id;
  const hostsTotal = scan.counts?.hosts_connected ?? 0;

  // ---- URL state
  const P = $derived({
    group_by: route.query.get('group_by') ?? (hostsTotal <= 60 ? 'host' : 'subnet'),
    metric: route.query.get('metric') ?? 'hosts',
    layer: route.query.get('layer') ?? 'access',
    unknown: route.query.get('unknown') !== '0',
    src: route.query.get('src') ?? '',
    dst: route.query.get('dst') ?? '',
    sort: route.query.get('sort') ?? 'volume',
    view: route.query.get('view') ?? 'matrix',
  });
  const drilled = $derived(!!(P.src || P.dst));
  const res = new Resource<any>();
  let renderMs = $state(0);
  let t0 = 0;
  const load = () => {
    t0 = performance.now();
    res.load(() => api(`/scans/${sid}/heatmap` + qs({ group_by: P.group_by, metric: P.metric, layer: P.layer,
      include_unknown: P.unknown ? 'true' : 'false', src_group: P.src || undefined, dst_group: P.dst || undefined })));
  };
  $effect(() => { P.group_by; P.metric; P.layer; P.unknown; P.src; P.dst; load(); });

  // ---- derived matrix in display order
  const hm = $derived(res.data);
  const hostLevel = $derived(hm ? hm.level === 'hosts' || hm.group_by === 'host' : false);
  const order = $derived.by(() => {
    if (!hm) return { rows: [] as number[], cols: [] as number[], rt: [] as number[], ct: [] as number[] };
    const rt = new Array(hm.rows.length).fill(0), ct = new Array(hm.cols.length).fill(0);
    for (const [r, c, v] of hm.cells) { rt[r] += v; ct[c] += v; }
    const last = (x: any) => (x.kind === 'unknown' ? 2 : x.kind === 'other' ? 1 : 0);
    const nat = (a: string, b: string) => a.localeCompare(b, 'en', { numeric: true });
    const sortIdx = (items: any[], tot: number[]) => items.map((_: any, i: number) => i).sort((a: number, b: number) =>
      last(items[a]) - last(items[b]) || (P.sort === 'volume' ? tot[b] - tot[a] : 0) || nat(items[a].label, items[b].label));
    return { rows: sortIdx(hm.rows, rt), cols: sortIdx(hm.cols, ct), rt, ct };
  });
  const grid = $derived.by(() => {
    const m = new Map<number, number>();
    if (hm) for (const [r, c, v] of hm.cells) m.set(r * 100000 + c, v);
    return m;
  });
  const val = (r: number, c: number) => grid.get(r * 100000 + c) ?? 0;
  const suffix = $derived(hm && hostLevel ? commonSuffix([...hm.rows, ...hm.cols].filter((x: any) => x.kind === 'host').map((x: any) => x.label)) : '');
  const unknownRowPos = $derived(hm ? order.rows.findIndex((i) => hm.rows[i].kind === 'unknown') : -1);

  // ---- geometry
  const GUTTER = 128, BARW = 64, TOPBAR = 32, COLLAB = 96, UGAP = 6;
  let paneW = $state(800);
  const pitch = $derived(hm ? Math.max(6, Math.min(28, Math.floor((paneW - GUTTER - BARW) / Math.max(1, hm.cols.length)))) : 28);
  const gap = $derived(pitch >= 10 ? 1 : 0);
  const W = $derived(hm ? hm.cols.length * pitch : 0);
  const H = $derived(hm ? order.rows.length * pitch + (unknownRowPos >= 0 ? UGAP : 0) : 0);
  const rowY = (pos: number) => pos * pitch + (unknownRowPos >= 0 && pos >= unknownRowPos ? UGAP : 0);
  const labelEvery = $derived(pitch >= 12 ? 1 : Math.ceil(12 / pitch));

  // ---- interaction state
  let hover = $state<{ r: number; c: number } | null>(null);       // display positions
  let active = $state<{ r: number; c: number }>({ r: 0, c: 0 });
  let focused = $state(false);
  let highlightHost = $state<number | null>(null);
  let mouse = $state({ x: 0, y: 0 });
  let pointerTip = $state(false);
  const cur = $derived(hover ?? (focused ? active : null));

  let cvCells = $state<HTMLCanvasElement>(), cvOver = $state<HTMLCanvasElement>(), cvRows = $state<HTMLCanvasElement>(), cvCols = $state<HTMLCanvasElement>(), cvBars = $state<HTMLCanvasElement>();
  let pal: Palette;

  function labelText(x: any): string {
    if (x.kind === 'other') return `Other (${x.groups} groups)`;
    if (x.kind === 'unknown') return 'Unknown origin';
    if (x.kind === 'unknown_key') { const fp = x.fp.replace('SHA256:', ''); return `? SHA256:${fp.slice(0, 4)}…${fp.slice(-4)}`; }
    if (x.kind === 'host' && suffix && x.label.endsWith(suffix)) return x.label.slice(0, -suffix.length);
    return x.label;
  }

  function drawAll() {
    if (!hm || !cvCells) return;
    pal = palette();
    const ctx = setupCanvas(cvCells, W, H);
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = pal.surface;
    ctx.fillRect(0, 0, W, H);
    const hatchDiag = hatch(ctx, pal.subtle, 1, 4);
    const hatchUnk = hatch(ctx, pal.primary, 0.2, 4);
    ctx.font = `500 11px 'IBM Plex Sans Condensed', system-ui, sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    const s = pitch - gap;
    order.rows.forEach((ri, pr) => {
      const y = rowY(pr);
      const unk = hm.rows[ri].kind === 'unknown' || hm.rows[ri].kind === 'unknown_key';
      order.cols.forEach((ci, pc) => {
        const x = pc * pitch;
        const v = val(ri, ci);
        const st = step(v);
        const diagonal = hm.rows[ri].id === hm.cols[ci].id && hm.rows[ri].kind !== 'other';
        ctx.fillStyle = pal.ramp[st];
        ctx.fillRect(x, y, s, s);
        if (diagonal && hostLevel && v === 0 && hatchDiag) { ctx.fillStyle = hatchDiag; ctx.fillRect(x, y, s, s); }
        else if (diagonal && !hostLevel) { ctx.strokeStyle = pal.strong; ctx.lineWidth = 1; ctx.strokeRect(x + 0.5, y + 0.5, s - 1, s - 1); }
        if (unk && v > 0 && hatchUnk) { ctx.fillStyle = hatchUnk; ctx.fillRect(x, y, s, s); }
        if (v > 0 && pitch >= 20) {
          ctx.fillStyle = pal.ink[st];
          ctx.fillText(String(v), x + s / 2, y + s / 2 + 0.5);
        }
      });
    });
    if (unknownRowPos >= 0) {
      const y = rowY(unknownRowPos) - UGAP / 2;
      ctx.strokeStyle = pal.strong;
      ctx.setLineDash([4, 3]);
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
      ctx.setLineDash([]);
    }
    drawLabels();
    drawBars();
    drawOverlay();
    renderMs = Math.max(1, Math.round(performance.now() - t0));
  }

  function plate(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number) {
    ctx.fillStyle = pal.raised;
    ctx.fillRect(x, y, w, h);
  }

  function drawLabels() {
    if (!hm || !cvRows) return;
    const cr = cur?.r, cc = cur?.c;
    // rows
    let ctx = setupCanvas(cvRows, GUTTER, H);
    ctx.clearRect(0, 0, GUTTER, H);
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'right';
    const hlRow = highlightHost !== null ? order.rows.findIndex((i) => hm.rows[i].host_id === highlightHost) : -1;
    order.rows.forEach((ri, pr) => {
      const it = hm.rows[ri];
      const isCur = pr === cr || pr === hlRow;
      if (!isCur && pr % labelEvery !== 0 && it.kind !== 'unknown' && it.kind !== 'other') return;
      const y = rowY(pr) + (pitch - gap) / 2;
      ctx.font = isCur ? `600 11px 'IBM Plex Sans Condensed', system-ui, sans-serif` : it.kind === 'other' ? `italic 400 11px 'IBM Plex Sans', system-ui, sans-serif` : `500 11px 'IBM Plex Sans Condensed', system-ui, sans-serif`;
      let maxw = GUTTER - 8;
      let lead = 0;
      if (it.kind === 'unknown' || it.kind === 'unknown_key' || it.status === 'partial') lead = 14;
      const txt = fitText(ctx, labelText(it), maxw - lead);
      const tw = ctx.measureText(txt).width;
      if (isCur) plate(ctx, GUTTER - 6 - tw - lead - 4, y - 8, tw + lead + 8, 16);
      ctx.fillStyle = isCur ? pal.primary : it.kind === 'other' ? pal.muted : pal.secondary;
      ctx.fillText(txt, GUTTER - 6, y);
      if (lead) {
        const gx = GUTTER - 6 - tw - 12;
        if (it.status === 'partial') { // diamond = partial
          ctx.fillStyle = pal.medium;
          ctx.beginPath(); ctx.moveTo(gx + 5, y - 5); ctx.lineTo(gx + 10, y); ctx.lineTo(gx + 5, y + 5); ctx.lineTo(gx, y); ctx.fill();
        } else { // dashed circle with ? = unknown origin
          ctx.strokeStyle = pal.secondary; ctx.setLineDash([2, 1.5]); ctx.lineWidth = 1.2;
          ctx.beginPath(); ctx.arc(gx + 5, y, 4.5, 0, Math.PI * 2); ctx.stroke(); ctx.setLineDash([]);
          ctx.fillStyle = pal.secondary; ctx.font = `600 8px 'IBM Plex Sans', sans-serif`; ctx.textAlign = 'center';
          ctx.fillText('?', gx + 5, y + 0.5); ctx.textAlign = 'right';
        }
      }
    });
    // columns: rotated -90°, reading bottom-to-top, above the margin strip
    ctx = setupCanvas(cvCols!, W, COLLAB + TOPBAR);
    ctx.clearRect(0, 0, W, COLLAB + TOPBAR);
    const hlCol = highlightHost !== null ? order.cols.findIndex((i) => hm.cols[i].host_id === highlightHost) : -1;
    order.cols.forEach((ci, pc) => {
      const it = hm.cols[ci];
      const isCur = pc === cc || pc === hlCol;
      if (!isCur && pc % labelEvery !== 0 && it.kind !== 'other') return;
      const x = pc * pitch + (pitch - gap) / 2;
      ctx.save();
      ctx.translate(x, COLLAB - 6);
      ctx.rotate(-Math.PI / 2);
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      ctx.font = isCur ? `600 11px 'IBM Plex Sans Condensed', system-ui, sans-serif` : it.kind === 'other' ? `italic 400 11px 'IBM Plex Sans', system-ui, sans-serif` : `500 11px 'IBM Plex Sans Condensed', system-ui, sans-serif`;
      const lead = it.status === 'partial' ? 14 : 0;
      const txt = fitText(ctx, labelText(it), COLLAB - 10 - lead);
      const tw = ctx.measureText(txt).width;
      if (isCur) plate(ctx, -2, -8, tw + lead + 6, 16);
      if (lead) {
        ctx.fillStyle = pal.medium;
        ctx.beginPath(); ctx.moveTo(0, 0); ctx.lineTo(5, -5); ctx.lineTo(10, 0); ctx.lineTo(5, 5); ctx.fill();
      }
      ctx.fillStyle = isCur ? pal.primary : it.kind === 'other' ? pal.muted : pal.secondary;
      ctx.fillText(txt, lead, 0);
      ctx.restore();
    });
    drawTopBars(ctx);
  }

  function drawTopBars(ctx: CanvasRenderingContext2D) {
    // top strip: inbound total per column (linear, shared scale), text.secondary at 45 %
    const maxC = Math.max(1, ...order.ct);
    const y0 = COLLAB, h = TOPBAR - 4;
    const sc = scaleLinear().domain([0, maxC]).range([0, h]);
    ctx.globalAlpha = 0.45;
    ctx.fillStyle = pal.secondary;
    order.cols.forEach((ci, pc) => {
      const bh = sc(order.ct[ci]);
      if (bh > 0) ctx.fillRect(pc * pitch, y0 + h - bh, Math.max(1, pitch - gap), bh);
    });
    ctx.globalAlpha = 1;
  }

  function drawBars() {
    if (!hm || !cvBars) return;
    const ctx = setupCanvas(cvBars, BARW, H);
    ctx.clearRect(0, 0, BARW, H);
    const maxR = Math.max(1, ...order.rt);
    const top10 = new Set([...order.rows].sort((a, b) => order.rt[b] - order.rt[a]).slice(0, 10).filter((i) => order.rt[i] > 0));
    const showNum = pitch >= 10;
    const barMax = showNum ? BARW - 40 : BARW - 6;
    const sc = scaleLinear().domain([0, maxR]).range([0, barMax]);
    ctx.font = `500 11px 'IBM Plex Sans Condensed', system-ui, sans-serif`;
    ctx.textBaseline = 'middle';
    order.rows.forEach((ri, pr) => {
      const y = rowY(pr);
      const bw = sc(order.rt[ri]);
      ctx.globalAlpha = 0.45;
      ctx.fillStyle = pal.secondary;
      if (bw > 0) ctx.fillRect(4, y + (pitch >= 10 ? 2 : 0), bw, Math.max(1, pitch - gap - (pitch >= 10 ? 4 : 0)));
      ctx.globalAlpha = 1;
      if (showNum && top10.has(ri)) {
        ctx.fillStyle = pal.secondary;
        ctx.fillText(n(order.rt[ri]), 4 + bw + 3, y + (pitch - gap) / 2);
      }
    });
  }

  function drawOverlay() {
    if (!hm || !cvOver) return;
    const ctx = setupCanvas(cvOver, W, H);
    ctx.clearRect(0, 0, W, H);
    const hlRow = highlightHost !== null ? order.rows.findIndex((i) => hm.rows[i].host_id === highlightHost) : -1;
    const hlCol = highlightHost !== null ? order.cols.findIndex((i) => hm.cols[i].host_id === highlightHost) : -1;
    ctx.strokeStyle = pal.primary;
    ctx.globalAlpha = 0.3;
    ctx.lineWidth = 1;
    const band = (r: number, c: number) => {
      if (r >= 0) ctx.strokeRect(0.5, rowY(r) - 0.5, W - 1, pitch);
      if (c >= 0) ctx.strokeRect(c * pitch - 0.5, 0.5, pitch, H - 1);
    };
    band(hlRow, hlCol);
    if (cur) band(cur.r, cur.c);
    ctx.globalAlpha = 1;
    if (cur) {
      ctx.lineWidth = 2;
      ctx.strokeRect(cur.c * pitch - 1, rowY(cur.r) - 1, pitch - gap + 2, pitch - gap + 2);
    }
  }

  // redraw on data, geometry, sort and theme changes
  $effect(() => {
    hm; W; H; pitch; order; theme.resolved; suffix; P.view;
    tick().then(drawAll);
  });
  $effect(() => { cur; highlightHost; if (hm && pal) { drawLabels(); drawOverlay(); } });

  // ---- pointer
  function posAt(e: MouseEvent): { r: number; c: number } | null {
    const rect = cvCells!.getBoundingClientRect();
    const x = e.clientX - rect.left, y = e.clientY - rect.top;
    const c = Math.floor(x / pitch);
    let r = -1;
    for (let pr = 0; pr < order.rows.length; pr++) { const ry = rowY(pr); if (y >= ry && y < ry + pitch) { r = pr; break; } }
    if (r < 0 || c < 0 || c >= order.cols.length) return null;
    return { r, c };
  }
  function onMove(e: MouseEvent) {
    const p = posAt(e);
    mouse = { x: e.clientX, y: e.clientY };
    pointerTip = true;
    if (!p) { hover = null; return; }
    if (!hover || hover.r !== p.r || hover.c !== p.c) { hover = p; requestPairs(p); }
  }
  function onLeave() { hover = null; pointerTip = false; }
  function onClick(e: MouseEvent) { const p = posAt(e); if (p) activate(p); }

  function cellAt(p: { r: number; c: number }) {
    const ri = order.rows[p.r], ci = order.cols[p.c];
    return { row: hm.rows[ri], col: hm.cols[ci], v: val(ri, ci) };
  }
  let drawer = $state<{ title: string; params: Record<string, any> } | null>(null);
  const drawerRes = new Resource<any>();
  function activate(p: { r: number; c: number }) {
    const { row, col, v } = cellAt(p);
    if (hostLevel) {
      if (v === 0 && row.id !== col.id) { /* empty pair: still list (nothing) */ }
      const params: Record<string, any> = { kind: P.layer, dst_host_id: col.host_id, page_size: 1000 };
      if (row.kind === 'unknown_key') { params.fp = row.fp; params.unknown_origin = true; }
      else if (row.kind === 'unknown') { params.unknown_origin = true; }
      else params.src_host_id = row.host_id;
      drawer = { title: `${row.kind === 'host' ? row.label : labelText(row)} → ${col.label}`, params };
      drawerRes.load(() => api(`/scans/${sid}/edges` + qs(params)));
    } else {
      setQuery({ src: row.id, dst: col.id });
    }
  }
  function labelClick(kind: 'row' | 'col', e: MouseEvent) {
    if (!hm) return;
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    let idx = -1;
    if (kind === 'row') {
      const y = e.clientY - rect.top;
      for (let pr = 0; pr < order.rows.length; pr++) { const ry = rowY(pr); if (y >= ry && y < ry + pitch) { idx = pr; break; } }
    } else idx = Math.floor((e.clientX - rect.left) / pitch);
    if (idx < 0) return;
    const it = kind === 'row' ? hm.rows[order.rows[idx]] : hm.cols[order.cols[idx]];
    if (!it) return;
    if (it.kind === 'host') navigate(hostHref(sid, it.host_id));
    else if (it.kind === 'unknown_key') navigate(keyHref(sid, it.fp));
    else if (!hostLevel) setQuery(kind === 'row' ? { src: it.id, dst: '*' } : { src: '*', dst: it.id });
  }

  // ---- tooltip pairs (fetched after 150 ms, cached)
  const pairCache = new Map<string, any>();
  let pairs = $state<any>(null);
  let pairTimer: number | undefined;
  function pairKey(p: { r: number; c: number }) {
    const { row, col } = cellAt(p);
    return { key: `${hm.level}|${hostLevel ? 'host' : P.group_by}|${P.metric}|${P.layer}|${row.id}|${col.id}`, row, col };
  }
  function requestPairs(p: { r: number; c: number }) {
    clearTimeout(pairTimer);
    const { key, row, col } = pairKey(p);
    if (pairCache.has(key)) { pairs = { key, ...pairCache.get(key) }; return; }
    pairs = null;
    if (cellAt(p).v === 0) return;
    pairTimer = window.setTimeout(async () => {
      const gb = hostLevel ? 'host' : P.group_by;
      const src = row.kind === 'unknown_key' ? row.id : row.id;
      try {
        const r = await api(`/scans/${sid}/heatmap/cell` + qs({ group_by: gb, metric: P.metric, layer: P.layer, src_group: src, dst_group: col.id }));
        pairCache.set(key, r);
        if (cur && pairKey(cur).key === key) pairs = { key, ...r };
      } catch { /* the tooltip keeps its value line */ }
    }, 150);
  }
  const tipCell = $derived(cur && hm ? cellAt(cur) : null);
  const tipPairs = $derived(cur && pairs && hm && pairs.key === pairKey(cur).key ? pairs : null);
  const unitWord = (v: number) => P.metric === 'hosts' ? (v === 1 ? 'host pair' : 'host pairs') : P.metric === 'users' ? (v === 1 ? 'user pair' : 'user pairs') : (v === 1 ? 'key' : 'keys');
  let tipEl: HTMLElement | undefined = $state();
  const tipPos = $derived.by(() => {
    if (!cur || !hm) return { x: 0, y: 0 };
    let x: number, y: number;
    if (pointerTip && hover) { x = mouse.x + 12; y = mouse.y + 12; }
    else if (cvCells) { const rc = cvCells.getBoundingClientRect(); x = rc.left + (cur.c + 1) * pitch + 12; y = rc.top + rowY(cur.r) + pitch + 12; }
    else { x = 0; y = 0; }
    const w = tipEl?.offsetWidth ?? 280, h = tipEl?.offsetHeight ?? 120;
    if (x + w > window.innerWidth - 8) x = x - w - 24;
    if (y + h > window.innerHeight - 8) y = y - h - 24;
    return { x: Math.max(8, x), y: Math.max(8, y) };
  });
  const shortFp = (fp: string) => { const b = fp.replace(/^unknown:/, '').replace('SHA256:', ''); return `SHA256:${b.slice(0, 4)}…${b.slice(-4)}`; };

  // ---- keyboard grid (design §8)
  let live = $state('');
  function announce() {
    if (!hm) return;
    const { row, col, v } = cellAt(active);
    live = `${labelText(row)} to ${labelText(col)}: ${v} ${unitWord(v)}`;
  }
  function onKey(e: KeyboardEvent) {
    if (!hm) return;
    const R = order.rows.length - 1, C = order.cols.length - 1;
    let { r, c } = active;
    switch (e.key) {
      case 'ArrowUp': r--; break;
      case 'ArrowDown': r++; break;
      case 'ArrowLeft': if (e.altKey) return; c--; break;
      case 'ArrowRight': c++; break;
      case 'Home': if (e.ctrlKey) { r = 0; } c = 0; break;
      case 'End': if (e.ctrlKey) { r = R; } c = C; break;
      case 'PageUp': r -= 10; break;
      case 'PageDown': r += 10; break;
      case 'Enter': case ' ': e.preventDefault(); activate(active); return;
      case 't': case 'T': e.preventDefault(); setQuery({ view: 'table' }); return;
      default: return;
    }
    e.preventDefault();
    active = { r: Math.max(0, Math.min(R, r)), c: Math.max(0, Math.min(C, c)) };
    hover = null;
    pointerTip = false;
    requestPairs(active);
    announce();
    scrollCellIntoView();
  }
  let scroller = $state<HTMLElement>();
  function scrollCellIntoView() {
    if (!scroller) return;
    const x = GUTTER + active.c * pitch, y = COLLAB + TOPBAR + rowY(active.r);
    if (x - GUTTER < scroller.scrollLeft) scroller.scrollLeft = x - GUTTER;
    if (x + pitch > scroller.scrollLeft + scroller.clientWidth - BARW) scroller.scrollLeft = x + pitch - scroller.clientWidth + BARW;
    if (y - COLLAB - TOPBAR < scroller.scrollTop) scroller.scrollTop = y - COLLAB - TOPBAR;
    if (y + pitch > scroller.scrollTop + scroller.clientHeight) scroller.scrollTop = y + pitch - scroller.clientHeight;
  }
  function up() { if (drilled) history.back(); }
  function globalKey(e: KeyboardEvent) {
    const t = e.target as HTMLElement;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'SELECT' || t.tagName === 'TEXTAREA')) return;
    if (drawer) return;
    if (drilled && (e.key === 'Backspace' || (e.altKey && e.key === 'ArrowLeft'))) { e.preventDefault(); setQuery({ src: null, dst: null }); }
  }

  // ---- pane width
  let pane: HTMLElement | undefined = $state();
  let ro: ResizeObserver | undefined;
  $effect(() => {
    if (!pane) return;
    ro?.disconnect();
    ro = new ResizeObserver(() => { paneW = pane!.clientWidth - 32; });
    ro.observe(pane);
    paneW = pane.clientWidth - 32;
  });
  onDestroy(() => ro?.disconnect());

  // ---- ranking
  const rank = new Resource<any>();
  const R = $derived({ dir: route.query.get('rdir') ?? 'in', metric: route.query.get('rmetric') ?? 'hosts' });
  $effect(() => { R.dir; R.metric; rank.load(() => api(`/scans/${sid}/ranking` + qs({ direction: R.dir, metric: R.dir === 'out' && R.metric === 'unknown_keys' ? 'hosts' : R.metric, limit: 25 })), true); });
  const rankMax = $derived(Math.max(1, ...(rank.data?.items ?? []).map((x: any) => x.value)));

  // ---- table view
  let tsort = $state<'value' | 'src' | 'dst'>('value');
  const tableRows = $derived.by(() => {
    if (!hm) return [];
    const rows = hm.cells.filter((c: number[]) => c[2] > 0).map(([r, c, v]: number[]) => ({ r, c, v, src: labelText(hm.rows[r]), dst: labelText(hm.cols[c]), row: hm.rows[r], col: hm.cols[c] }));
    const nat = (a: string, b: string) => a.localeCompare(b, 'en', { numeric: true });
    rows.sort((a: any, b: any) => tsort === 'value' ? b.v - a.v || nat(a.src, b.src) : tsort === 'src' ? nat(a.src, b.src) || b.v - a.v : nat(a.dst, b.dst) || b.v - a.v);
    return rows;
  });
  function tableActivate(t: any) {
    const pr = order.rows.indexOf(t.r), pc = order.cols.indexOf(t.c);
    activate({ r: pr, c: pc });
  }

  const empty = $derived(hm && hm.cells.length === 0);
  const crumbs = $derived(hm && hm.level === 'hosts' ? { src: hm.src_label, dst: hm.dst_label } : null);
  let exportOpen = $state(false);
  const metricSentence = $derived(P.metric === 'hosts' ? 'distinct host pairs' : P.metric === 'users' ? 'user pairs' : 'keys');
  const GROUPS: [string, string][] = [['host', 'Host'], ['subnet', 'Subnet'], ['ansible', 'Ansible group'], ['tag', 'Tag'], ['depth', 'Crawl depth']];
</script>

<svelte:window onkeydown={globalKey} onclick={(e) => { if (!(e.target as HTMLElement).closest('.exp')) exportOpen = false; }} />

<PageHead title="Heatmap · {P.layer === 'access' ? 'access, effective only' : 'evidence'}">
  {#snippet sub()}{#if P.layer === 'evidence'}Evidence – known_hosts and ssh config references, not access{/if}{/snippet}
  {#snippet actions()}
    <button class="btn" aria-pressed={P.view === 'table'} onclick={() => setQuery({ view: P.view === 'table' ? null : 'table' })}>{P.view === 'table' ? 'Matrix view' : 'Table view'}</button>
    <div class="exp">
      <button class="btn" aria-haspopup="menu" aria-expanded={exportOpen} onclick={() => (exportOpen = !exportOpen)}>Export edges ▾</button>
      {#if exportOpen}<div class="popover expmenu" role="menu">
        <a role="menuitem" href="/api/scans/{sid}/export/edges.csv?kind={P.layer}" download>Edges (CSV)</a>
        <a role="menuitem" href="/api/scans/{sid}/export/edges.json?kind={P.layer}" download>Edges (JSON)</a>
      </div>{/if}
    </div>
  {/snippet}
</PageHead>
<Notices {scan} partial />

<div class="filters">
  <label class="row meta secondary">Group by
    <select class="select" value={P.group_by} onchange={(e) => setQuery({ group_by: (e.target as HTMLSelectElement).value, src: null, dst: null })}>
      {#each GROUPS as [v, l]}<option value={v}>{l}</option>{/each}
    </select></label>
  <label class="row meta secondary">Metric
    <select class="select" value={P.metric} onchange={(e) => setQuery({ metric: (e.target as HTMLSelectElement).value === 'hosts' ? null : (e.target as HTMLSelectElement).value })}>
      <option value="hosts">Hosts</option><option value="users">Users</option><option value="keys" disabled={P.layer === 'evidence'}>Keys</option>
    </select></label>
  <div class="seg" role="radiogroup" aria-label="Layer">
    <button role="radio" aria-checked={P.layer === 'access'} onclick={() => setQuery({ layer: null })}>Access</button>
    <button role="radio" aria-checked={P.layer === 'evidence'} onclick={() => setQuery({ layer: 'evidence', metric: P.metric === 'keys' ? null : P.metric })}>Evidence</button>
  </div>
  {#if P.layer === 'access'}<label class="check"><input type="checkbox" checked={P.unknown} onchange={(e) => setQuery({ unknown: (e.target as HTMLInputElement).checked ? null : '0' })} />Unknown-origin row</label>{/if}
  <div class="seg" role="radiogroup" aria-label="Sort">
    <button role="radio" aria-checked={P.sort === 'volume'} onclick={() => setQuery({ sort: null }, true)}>Volume</button>
    <button role="radio" aria-checked={P.sort === 'name'} onclick={() => setQuery({ sort: 'name' }, true)}>Name</button>
  </div>
</div>

{#if crumbs}
  <nav class="crumbs" aria-label="Breadcrumb">
    <a href={location.pathname + qs({ group_by: route.query.get('group_by'), metric: route.query.get('metric'), layer: route.query.get('layer'), unknown: route.query.get('unknown'), sort: route.query.get('sort') })}>All groups</a>
    <span class="muted">{' › '}</span><span class="mono" aria-current="page">{crumbs.src} → {crumbs.dst}</span>
  </nav>
{/if}

<div class="grid-2 hmgrid">
  <section class="panel matrix-panel" bind:this={pane}>
    {#if res.error}
      <ErrorPanel thing="the heatmap" message={res.error} retry={load} />
    {:else if !hm}
      <div class="building" style:width="{Math.min(paneW, 640)}px" style:height="{Math.min(560, 28 * Math.max(4, Math.min(20, hostsTotal)) + 128)}px"><span class="secondary">Building heatmap…</span></div>
    {:else if empty && !(hm.include_unknown && hm.rows.some((r: any) => r.kind === 'unknown'))}
      <p class="emptymsg">{P.layer === 'evidence' ? 'No known_hosts or ssh config references point to scanned hosts.' : `No access between scanned hosts in scan #${sid}.`}</p>
    {:else}
      {#if hm.level === 'hosts' && hm.hidden > 0}<p class="meta secondary trunc-note">Showing the top {Math.min(100, hm.rows_total)} × {Math.min(100, hm.cols_total)} hosts by total; {n(hm.hidden)} more hosts hidden.</p>{/if}
      {#if !drilled && hm.rows.some((r: any) => r.kind === 'other')}<p class="meta secondary trunc-note">More than 60 groups: the smallest are folded into “Other”.</p>{/if}
      {#if P.view === 'table'}
        <div class="table-wrap tv">
          <table class="t">
            <thead><tr>
              <th aria-sort={tsort === 'src' ? 'ascending' : 'none'}><button class="sort" onclick={() => (tsort = 'src')}>Source{#if tsort === 'src'} ▲{/if}</button></th>
              <th aria-sort={tsort === 'dst' ? 'ascending' : 'none'}><button class="sort" onclick={() => (tsort = 'dst')}>Destination{#if tsort === 'dst'} ▲{/if}</button></th>
              <th class="r" aria-sort={tsort === 'value' ? 'descending' : 'none'}><button class="sort" onclick={() => (tsort = 'value')}>Value{#if tsort === 'value'} ▼{/if}</button></th>
            </tr></thead>
            <tbody>
              {#each tableRows as t}
                <tr class="clickable" onclick={() => tableActivate(t)}>
                  <td class="mono">{#if t.row.kind === 'unknown' || t.row.kind === 'unknown_key'}<span class="sev-info unk"><Glyph kind="unknown" /></span>{/if}{t.src}</td>
                  <td class="mono">{t.dst}</td>
                  <td class="r num"><button class="linkish" onclick={(e) => { e.stopPropagation(); tableActivate(t); }}>{t.v}</button></td>
                </tr>
              {:else}<tr><td class="empty" colspan="3">No access between scanned hosts in scan #{sid}.</td></tr>{/each}
            </tbody>
          </table>
        </div>
      {:else}
        <div class="scroller" bind:this={scroller}>
          <div class="mgrid" style:grid-template-columns="{GUTTER}px {W}px {BARW}px" style:grid-template-rows="{COLLAB + TOPBAR}px {H}px">
            <div class="corner c1"></div>
            <canvas class="cols" bind:this={cvCols} onclick={(e) => labelClick('col', e)} aria-hidden="true"></canvas>
            <div class="corner c2"></div>
            <canvas class="rows" bind:this={cvRows} onclick={(e) => labelClick('row', e)} aria-hidden="true"></canvas>
            <div class="cellwrap">
              <canvas class="cells" bind:this={cvCells} tabindex="0" role="grid" data-pitch={pitch} data-gap={gap} data-rendered={renderMs}
                data-rows={order.rows.map((i) => hm.rows[i].label).join('|')} data-cols={order.cols.map((i) => hm.cols[i].label).join('|')}
                data-unknown-pos={unknownRowPos}
                aria-label="Access heatmap, {hm.rows.length} sources by {hm.cols.length} destinations"
                onmousemove={onMove} onmouseleave={onLeave} onclick={onClick} onkeydown={onKey}
                onfocus={() => { focused = true; announce(); }} onblur={() => (focused = false)}></canvas>
              <canvas class="over" bind:this={cvOver} aria-hidden="true"></canvas>
            </div>
            <canvas class="bars" bind:this={cvBars} aria-hidden="true"></canvas>
          </div>
        </div>
        <div class="sr-only" aria-live="polite">{live}</div>
      {/if}
      <div class="legend">
        <div class="bins" aria-label="Legend">
          {#each BINS as b}<span class="bin"><span class="sw sw{b.step}"></span><span class="micro num">{b.label}</span></span>{/each}
        </div>
        <p class="meta secondary">Colour = {metricSentence}{#if P.layer === 'access' && P.unknown}{' · '}<span class="hatchsw" aria-hidden="true"></span> Hatched = unknown origin (no private key found){/if}</p>
        <p class="meta secondary">{P.layer === 'access' ? 'Counts only effective access edges; self-access is not counted.' : 'Counts evidence edges.'}{#if suffix}{' · '}Hidden suffix: <span class="mono">{suffix}</span>{/if}
          {#if renderMs}{' · '}<span class="num">{hm.hosts_total} hosts, built in {renderMs} ms</span>{/if}</p>
        <p class="meta muted">{hostLevel ? 'Click a cell to list its edges; click a host label to open the host.' : 'Click a cell to drill down to host × host; click a label to drill into that group.'} Keyboard: arrow keys, Enter, Backspace, T.</p>
      </div>
    {/if}
  </section>

  <aside class="panel ranking">
    <h2 class="section-title">{R.dir === 'in' ? 'Most inbound' : 'Most outbound'}</h2>
    <div class="row rk">
      <div class="seg" role="radiogroup" aria-label="Direction">
        <button role="radio" aria-checked={R.dir === 'in'} onclick={() => setQuery({ rdir: null }, true)}>Inbound</button>
        <button role="radio" aria-checked={R.dir === 'out'} onclick={() => setQuery({ rdir: 'out', rmetric: R.metric === 'unknown_keys' ? null : R.metric }, true)}>Outbound</button>
      </div>
      <label class="row meta secondary">Metric
        <select class="select" value={R.metric} onchange={(e) => setQuery({ rmetric: (e.target as HTMLSelectElement).value === 'hosts' ? null : (e.target as HTMLSelectElement).value }, true)}>
          <option value="hosts">Hosts</option><option value="users">Users</option><option value="keys">Keys</option>
          {#if R.dir === 'in'}<option value="unknown_keys">Unknown-origin keys</option>{/if}
        </select></label>
    </div>
    {#if rank.error}<ErrorPanel thing="the ranking" message={rank.error} />
    {:else if rank.data}
      {#if rank.data.items.length === 0}<p class="secondary dense">{R.dir === 'in' ? 'No host can be reached from another scanned host.' : 'No host can reach another scanned host.'}</p>{/if}
      <ol class="rlist">
        {#each rank.data.items as r, i}
          <li onmouseenter={() => (highlightHost = r.host_id)} onmouseleave={() => (highlightHost = null)}>
            <span class="num muted">{i + 1}</span>
            <a class="mono trunc" href={hostHref(sid, r.host_id)} title={r.display_name}>{suffix && r.display_name.endsWith(suffix) ? r.display_name.slice(0, -suffix.length) : r.display_name}</a>
            <span class="num v">{n(r.value)}</span>
            <span class="rb"><span style:width="{(r.value / rankMax) * 100}%"></span></span>
          </li>
        {/each}
      </ol>
    {/if}
  </aside>
</div>

{#if cur && tipCell && tipCell.v > 0 && hm && P.view !== 'table' && !drawer}
  <div class="tooltip" bind:this={tipEl} style:left="{tipPos.x}px" style:top="{tipPos.y}px" role="tooltip">
    <div class="tt mono">{tipCell.row.kind === 'unknown' ? 'Unknown origin' : labelText(tipCell.row)} → {labelText(tipCell.col)}</div>
    {#if hostLevel && tipCell.row.kind === 'host'}
      <div class="secondary num">{plural(tipCell.v, P.metric === 'hosts' ? 'host pair' : P.metric === 'users' ? 'user pair' : 'key')}{#if tipPairs?.pairs?.[0]}{' · '}{plural(tipPairs.pairs[0].users, 'user')} · {plural(tipPairs.pairs[0].keys, 'key')}{/if}</div>
      <div class="meta muted">Click to list the edges</div>
    {:else}
      <div class="secondary num">{n(tipCell.v)} {unitWord(tipCell.v)} · {P.layer === 'access' ? 'access, effective' : 'evidence'}</div>
      {#if tipPairs}
        <div class="meta muted tp">Top pairs</div>
        <ul class="pairs">
          {#each tipPairs.pairs as p}
            <li class="mono"><span class="trunc">{p.src_host_id === null ? `? ${shortFp(p.src)} → ${p.dst}${p.dst_users?.[0] ? ':' + p.dst_users[0] : ''}` : `${suffix ? p.src.replace(suffix, '') : p.src} → ${suffix ? p.dst.replace(suffix, '') : p.dst}`}</span>
              <span class="num secondary sans">{P.metric === 'keys' ? plural(p.keys, 'key') : plural(p.users, 'user')}</span></li>
          {/each}
        </ul>
      {:else}<div class="meta muted">Loading top pairs…</div>{/if}
      <div class="meta muted">{hostLevel ? 'Click to list the edges' : 'Click to drill down'}</div>
    {/if}
  </div>
{/if}

{#if drawer}
  <Drawer title={drawer.title} onclose={() => (drawer = null)}>
    {#if drawerRes.error}<ErrorPanel thing="edges" message={drawerRes.error} />
    {:else if !drawerRes.data}<p class="secondary">Loading edges…</p>
    {:else}
      <p class="meta secondary">{plural(drawerRes.data.total, P.layer === 'access' ? 'access edge' : 'evidence edge')}</p>
      <EdgeTable edges={drawerRes.data.items} scan={sid} evidence={P.layer === 'evidence'} empty="No edges between these hosts." />
    {/if}
  </Drawer>
{/if}

<style>
  .crumbs { font-size: 13px; }
  .hmgrid { align-items: start; }
  .matrix-panel { min-width: 0; display: flex; flex-direction: column; gap: var(--s4); }
  .scroller { overflow: auto; max-height: max(560px, calc(100vh - 150px)); min-height: 200px; position: relative; max-width: 100%; }
  .mgrid { display: grid; width: max-content; }
  .corner { background: var(--bg-surface); position: sticky; top: 0; z-index: 3; }
  .c1 { left: 0; z-index: 4; }
  .c2 { right: 0; z-index: 4; }
  canvas { display: block; }
  .cols { position: sticky; top: 0; z-index: 2; background: var(--bg-surface); cursor: pointer; }
  .rows { position: sticky; left: 0; z-index: 1; background: var(--bg-surface); cursor: pointer; }
  .bars { position: sticky; right: 0; z-index: 1; background: var(--bg-surface); }
  .cellwrap { position: relative; }
  .cells { cursor: pointer; }
  .cells:focus-visible { outline: 2px solid var(--text-primary); outline-offset: 2px; }
  .over { position: absolute; left: 0; top: 0; pointer-events: none; }
  .building { border: 1px solid var(--border-strong); background: var(--bg-sunken); display: grid; place-items: center; max-width: 100%; }
  .emptymsg { padding: var(--s7); text-align: center; color: var(--text-secondary); }
  .trunc-note { margin: 0; }
  .legend { display: flex; flex-direction: column; gap: var(--s2); border-top: 1px solid var(--border-subtle); padding-top: var(--s3); }
  .bins { display: flex; flex-wrap: wrap; gap: var(--s3); align-items: center; }
  .bin { display: inline-flex; gap: var(--s2); align-items: center; }
  .sw { width: 16px; height: 12px; display: inline-block; }
  .sw0 { background: var(--bg-sunken); border: 1px solid var(--border-subtle); }
  .sw1 { background: var(--ramp-1); } .sw2 { background: var(--ramp-2); } .sw3 { background: var(--ramp-3); }
  .sw4 { background: var(--ramp-4); } .sw5 { background: var(--ramp-5); } .sw6 { background: var(--ramp-6); }
  .sw7 { background: var(--ramp-7); } .sw8 { background: var(--ramp-8); } .sw9 { background: var(--ramp-9); }
  .hatchsw { display: inline-block; width: 16px; height: 12px; vertical-align: -2px; background-color: var(--ramp-3);
    background-image: repeating-linear-gradient(45deg, color-mix(in srgb, var(--text-primary) 20%, transparent) 0 1px, transparent 1px 4px); }
  .ranking { display: flex; flex-direction: column; gap: var(--s4); }
  .rk { gap: var(--s3); }
  .rlist { list-style: none; margin: 0; padding: 0; }
  .rlist li { display: grid; grid-template-columns: 24px minmax(0, 1fr) 40px 30%; gap: var(--s3); align-items: center; height: 28px; font-size: 13px;
    padding: 0 var(--s2); border-radius: var(--r1); }
  .rlist li:hover { background: var(--bg-hover); }
  .rlist .v { text-align: right; }
  .rb span { display: block; height: 8px; background: var(--text-secondary); opacity: .45; }
  .tooltip .tt { font-weight: 500; }
  .tp { margin-top: var(--s2); }
  .pairs { list-style: none; margin: 0 0 var(--s2); padding: 0; }
  .pairs li { display: flex; justify-content: space-between; gap: var(--s4); font-size: 12px; line-height: 16px; }
  .pairs .trunc { max-width: 210px; }
  .sans { font-family: var(--sans); }
  .unk { color: var(--c); margin-right: var(--s2); }
  .tv { max-height: calc(100vh - 290px); }
  .linkish { all: unset; cursor: pointer; color: var(--accent); }
  .linkish:focus-visible { outline: 2px solid var(--accent); }
  .exp { position: relative; }
  .expmenu { right: 0; top: 36px; display: flex; flex-direction: column; padding: var(--s2) 0; min-width: 160px; z-index: 50; }
  .expmenu a { padding: var(--s3) var(--s4); color: var(--text-primary); }
  .expmenu a:hover { background: var(--bg-hover); text-decoration: none; }
  @media (max-width: 1279px) { .scroller { max-height: none; } }
</style>
