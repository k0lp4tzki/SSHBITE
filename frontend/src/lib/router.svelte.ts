// Minimal history router: filters live in the query string, so Back and shared links work (design §3).
export const route = $state({ path: location.pathname, search: location.search, query: new URLSearchParams(location.search) });

function sync() {
  route.path = location.pathname;
  route.search = location.search;
  route.query = new URLSearchParams(location.search);
}

export function navigate(url: string, replace = false) {
  if (url === location.pathname + location.search + location.hash) return;
  if (replace) history.replaceState(null, '', url);
  else history.pushState(null, '', url);
  sync();
  if (!replace && !url.includes('#')) window.scrollTo(0, 0);
}

/** Replace some query parameters of the current URL (empty values are removed). */
export function setQuery(params: Record<string, string | number | boolean | null | undefined>, replace = false) {
  const q = new URLSearchParams(location.search);
  for (const [k, v] of Object.entries(params)) {
    if (v === null || v === undefined || v === '' || v === false) q.delete(k);
    else q.set(k, String(v));
  }
  const s = q.toString();
  navigate(location.pathname + (s ? `?${s}` : ''), replace);
}

window.addEventListener('popstate', sync);
document.addEventListener('click', (e) => {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  const a = (e.target as Element).closest?.('a');
  if (!a) return;
  const href = a.getAttribute('href');
  if (!href || !href.startsWith('/') || href.startsWith('/api/') || a.target || a.hasAttribute('download')) return;
  e.preventDefault();
  navigate(href);
});
