// Heatmap encoding (design §2.3, §5.2): fixed log2 bins, the same in every view and at every scale.
export const BINS = [
  { step: 0, label: '0', lo: 0, hi: 0 },
  { step: 1, label: '1', lo: 1, hi: 1 },
  { step: 2, label: '2', lo: 2, hi: 2 },
  { step: 3, label: '3–4', lo: 3, hi: 4 },
  { step: 4, label: '5–8', lo: 5, hi: 8 },
  { step: 5, label: '9–16', lo: 9, hi: 16 },
  { step: 6, label: '17–32', lo: 17, hi: 32 },
  { step: 7, label: '33–64', lo: 33, hi: 64 },
  { step: 8, label: '65–128', lo: 65, hi: 128 },
  { step: 9, label: '≥129', lo: 129, hi: Infinity },
];

export function step(v: number): number {
  if (v <= 0) return 0;
  if (v === 1) return 1;
  if (v === 2) return 2;
  if (v <= 4) return 3;
  if (v <= 8) return 4;
  if (v <= 16) return 5;
  if (v <= 32) return 6;
  if (v <= 64) return 7;
  if (v <= 128) return 8;
  return 9;
}

export type Palette = {
  ramp: string[]; ink: string[]; sunken: string; surface: string; raised: string; subtle: string; strong: string;
  primary: string; secondary: string; muted: string; medium: string; dark: boolean;
};

export function palette(): Palette {
  const cs = getComputedStyle(document.documentElement);
  const v = (n: string) => cs.getPropertyValue(n).trim();
  const ramp = [v('--bg-sunken')];
  const ink = [''];
  for (let i = 1; i <= 9; i++) { ramp.push(v(`--ramp-${i}`)); ink.push(v(`--ink-${i}`)); }
  return {
    ramp, ink, sunken: v('--bg-sunken'), surface: v('--bg-surface'), raised: v('--bg-raised'), subtle: v('--border-subtle'),
    strong: v('--border-strong'), primary: v('--text-primary'), secondary: v('--text-secondary'), muted: v('--text-muted'),
    medium: v('--medium'), dark: document.documentElement.dataset.theme === 'dark',
  };
}

/** A small 45° hatch pattern. */
export function hatch(ctx: CanvasRenderingContext2D, color: string, alpha: number, gap = 4): CanvasPattern | null {
  const c = document.createElement('canvas');
  const dpr = window.devicePixelRatio || 1;
  c.width = c.height = Math.round(gap * dpr);
  const x = c.getContext('2d')!;
  x.scale(dpr, dpr);
  x.globalAlpha = alpha;
  x.strokeStyle = color;
  x.lineWidth = 1;
  x.beginPath();
  x.moveTo(0, gap); x.lineTo(gap, 0);
  x.moveTo(-1, 1); x.lineTo(1, -1);
  x.moveTo(gap - 1, gap + 1); x.lineTo(gap + 1, gap - 1);
  x.stroke();
  const p = ctx.createPattern(c, 'repeat');
  p?.setTransform(new DOMMatrix().scale(1 / dpr, 1 / dpr));
  return p;
}

export function setupCanvas(cv: HTMLCanvasElement, w: number, h: number): CanvasRenderingContext2D {
  const dpr = window.devicePixelRatio || 1;
  cv.width = Math.max(1, Math.round(w * dpr));
  cv.height = Math.max(1, Math.round(h * dpr));
  cv.style.width = `${w}px`;
  cv.style.height = `${h}px`;
  const ctx = cv.getContext('2d')!;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return ctx;
}

export function fitText(ctx: CanvasRenderingContext2D, s: string, max: number): string {
  if (ctx.measureText(s).width <= max) return s;
  let lo = 0, hi = s.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (ctx.measureText(s.slice(0, mid) + '…').width <= max) lo = mid; else hi = mid - 1;
  }
  return s.slice(0, lo) + '…';
}

/** Common domain suffix of all host labels (".synthetic.invalid"), or ''. */
export function commonSuffix(labels: string[]): string {
  const names = labels.filter((l) => l && !/^[\d.:]+$/.test(l) && l.includes('.'));
  if (names.length < 2 || names.length !== labels.length) return '';
  const parts = names.map((n) => n.split('.').slice(1));
  let k = 0;
  for (;;) {
    const seg = parts[0].length - 1 - k;
    if (seg < 0) break;
    const val = parts[0][seg];
    if (!parts.every((p) => p.length - 1 - k >= 0 && p[p.length - 1 - k] === val)) break;
    k++;
  }
  if (k === 0) return '';
  return '.' + parts[0].slice(parts[0].length - k).join('.');
}
