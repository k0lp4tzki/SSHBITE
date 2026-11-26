# Evidence for the polish package after check-12

Svelte frontend, browser tests and – for the cold start – the heatmap query path (`sshbite/web/data.py` `Views`,
two call sites in `app.py` and `api.py`). No change to the API contract, the data, the CLI, the collector or the lab.
Numbers, finding texts, routes, URLs, `aria-*` attributes and `data-testid`s are unchanged.

Screenshots: scan 1 is the **live lab scan** of the company's compose stack (`compose.yaml` → 13 OpenSSH hosts + the
SSHBITE image, built from commit a38c9b9), 1280×800, light theme unless the name says `dunkel` or `375`. The drill-down
is **synthetic** (`sshbite synth --hosts 2000 --seed 42`, served locally from the same commit). The measured values
behind each picture are in `walk.txt`.

| Item | Screenshot(s) in `screens/` | What it shows (from `walk.txt`) |
|---|---|---|
| 1 Graph | `01-graph-a2-hell-1280`, `01-graph-a2-dunkel-1280`, `01-graph-k_dsa-hell-1280`, `01-graph-jump-hops2-hell-1280`, `01-graph-a2-hell-reduced-motion-1280` | centre node 0 px from the pane centre in every case (662×520 pane); the nearest node edge sits 40 px from the pane edge on the tight axis; scale a2 1.495, K_DSA 1.5 (cap), jump with 2 hops 0.675; same with `prefers-reduced-motion` |
| 2 Users tab | `02-host-a2-users-hell-1280-ganz` | the column x positions are identical in every panel per table kind; 0 cells cut off; Origin visible; option chips wrap and have the common chip border |
| 3 Dashboard | `03-dashboard-hell-1280-ganz` | every recommendation in full, at most 2 lines ("Replace with ed25519, remove this line/file"); paths cut in the middle, full path in `title` |
| 4 Tabs at 375 px | `04-host-a2-tabs-vorher-hell-375`, `04-host-a2-tabs-nach-scrollen-hell-375`, `04-host-a2-tab-findings-hell-375` | fade and chevron on the right edge; after scrolling a chevron on both edges; Findings selected and scrolled into view; page 375 px wide |
| 5 Key label | `05-findings-label-k_dsa-hell-1280` | label “QA legacy dsa - remove” on its own line above "authorized key" |
| 6 Drill-down | `06-synth-drilldown-label-hover-hell-1280` | Group by reads "Host (drill-down)"; hovered row syn-0819 and column syn-0895 on an opaque plate, no neighbour label within 15 px |
| 7 Mono | `07-host-a2-sshd-hell-1280`, `07-host-a2-known-by-hell-1280` | yes / no / none / – in Sans; paths and AuthorizedKeysFile in Mono; "(hashed)" in Sans |
| 8 Search focus | `08-suche-fokus-per-tab-hell-1280` | after 12 Tab presses: outline solid 2px rgb(10, 108, 116), offset 2px – as every other control |

## Cold start (item 9)

`cold-start-timings.txt`, measured with `cold_start.py` (fresh synth DB and fresh `sshbite serve` per block):

| | before (8a12ef1) | after |
|---|---|---|
| API, first request / next three | 210 / 46 / 76 / 44 ms | 57 / 49 / 79 / 49 ms |
| Browser, heatmap as first page after login | 917 ms (page: built in 842 ms) | 351 ms (built in 234 ms) |
| Browser, scan written while the UI already runs | 981 ms (built in 820 ms) | 508 ms (built in 395 ms) |

Cause: the first heatmap request derived the scan view (2,000 hosts, ~19,000 edge rows) itself, and the heatmap
page's two parallel requests (matrix and ranking) both built that view at once under the GIL. No index was missing.
Fix: single-flight builds plus a background warm-up of the newest scans at server start and on every scan-list
read. check-12's 4.7 s could not be reproduced on this machine (worst here: 0.98 s before the fix).

## Test runs

| Suite | File | Result |
|---|---|---|
| unit + web API | `pytest-unit-web.txt` | 213 passed, none skipped |
| lab e2e against the stack's lab (`SSHBITE_LAB_ENTRY=jump:22`), scans 1–3 live with read-only snapshots | `pytest-e2e.txt` | 16 passed, none skipped |
| Playwright | `pytest-browser.txt` | 35 passed (29 earlier + 6 new), none skipped |
| ruff, svelte-check | `lint.txt` | ruff clean; svelte-check 0 errors (the 14 warnings are the ones that were already there) |

New Playwright checks (`tests/browser/test_ui.py`, end of file):
- `test_g1_graph_centre_in_the_middle_and_fitted[light/dark/light-reduced]` – for a2, K_DSA and jump with 2 hops, the centre
  node's centre is within 10 % of the pane centre, every node sits inside the pane with a margin, the graph reaches the
  40 px margin on one axis or the 1.5× cap, and "Fit" after a pan returns to the same view.
- `test_g2_users_tab_columns_line_up_and_nothing_is_cut` – same column x per table kind in every panel of a2, no cell
  cut off, one border colour for all chips.
- `test_g3_dashboard_recommendation_readable_and_tabs_at_375` – recommendations not clamped at 1280 px; at 375 px the
  scroll chevrons appear and the selected tab ends up inside the bar.
- `test_g4_drilldown_group_by_says_so` – Group by reads "Host (drill-down)", and picking Subnet leaves the drill-down.
