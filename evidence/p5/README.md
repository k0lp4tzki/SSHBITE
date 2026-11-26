# Evidence for the redesign package (design-revision v2)

Presentation only: no API, schema, CLI, collector or lab change. Built from this branch; the company's
compose stack (`compose.yaml` → lab demo: 13 OpenSSH hosts + the SSHBITE image) ran from commit de773c5.

| What | File |
|---|---|
| unit + web API | `pytest-unit-web.txt` – 213 passed, none skipped |
| lab e2e against the stack's lab (jump:22), scans 1–3 live with read-only snapshots | `pytest-e2e.txt` – 16 passed, none skipped |
| Playwright | `pytest-browser.txt` – 29 passed (23 earlier + 6 new design-revision §7 checks), none skipped |
| svelte-check, ruff | `lint.txt` |
| J4/J5 on the live stack (label saved, filtered export name) | `j4-j5-walk.txt` |

## New Playwright checks (`tests/browser/test_ui.py`)

- `test_r1_…[light|dark]` – §7.1: the computed colours of 13 main screens and the login contain no `#4338b8`,
  no `#f6f5f1` and no green (hue 75–170°, saturation > 0.15).
- `test_r3_…` – §7.3: every text element on the main screens, the drawer, the search popover and the login
  uses 11 (only in Condensed: heatmap legend), 12, 13, 14, 16 or 20 px; no `text-transform: uppercase`.
- `test_r4_…` – §7.4: no " · " in any text node, no link/button/tab/menu item ending in an arrow; the
  tooltip reads `jump → a2` / `1 host pair` on separate lines; the drawer has `Open jump` and `Open a2`.
- `test_r8_…` – §7.8: at 1280×800 the sidebar column of `/s/1/crawl` spans the whole page height and is
  under the pointer at the bottom after scrolling down; no horizontal overflow.
- `test_r_crawl_filter_…` – check-9 N3: on 2,000 synthetic hosts the crawl filter finds `syn-1987` (collapsed
  at first) by name and by IP.

## Assertions adapted (presentational details the revision removes)

| Test | Before | After | Why |
|---|---|---|---|
| `test_6_key_dsa` | `"origin:" in head` | `"Origin\nUnknown" in head` | Origin is a context field (label above value), §5.4 |
| `test_9_no_request_leaves_the_origin` | fonts checked on the last page (/diff) | one more `s.go("/s/1/findings")` before the font check | the Diff hosts tab no longer uses Mono (§3.4 Mono rule); the check itself is unchanged |
| `test_f1_route_attempts…` | button `"↺ 1 failed attempt"` | `"1 failed attempt"` | the ↺ glyph is gone, §5.8 |
| `test_f6_accounts_count_diff_route_removed` | sentence `route removed (was jump → b3 → c1 → c2)` / `privilege removed (was root)` in the row | rows `Route │ jump → b3 → c1 → c2 │ removed`, `Privilege │ root │ removed`, `Status │ OK │ Host key changed` in the row's Field/Before/After table; still no `→ –` | §5.6 and the CEO brief: Field │ Before │ After subtable |
| `test_f6_crawl_tree_reaches_every_one_of_2000_hosts` | selector `td.hcell a, td.hcell span.mono` | `td.hcell .hn` | host names are Sans now (§3.4), the class was the font class |

## Contrast (WCAG 2.x, computed from the tokens)

Dark theme, left open by the designer:
- text on its tint: Critical 5.47, High 6.10, Medium 7.37, Low 7.03, Info 4.54 – all ≥ 4.5, no tint changed.
- `text.muted` on `bg.subtle`: 5.04 (with the value below).

Adjusted: `text.muted` against `bg.hover`/`bg.selected` fell below 4.5 in the existing contrast test (light
4.39/4.29, dark 4.28 on `bg.selected`). `text.muted` moved one step: light `#667085` → `#626c81`
(4.55 min), dark `#8a93a2` → `#8f98a7` (4.56 min). The full table of every pair is written by
`test_c3_contrast_computed_in_both_themes` (`contrast-light.txt`, `contrast-dark.txt` with
`SSHBITE_EVIDENCE_DIR`).

## Screenshots (`/state/screens/`)

Scan 1 = the live lab scan of the stack (label "lab demo"). `fixture` = scans 2/3 from
`tests/fixtures/lab_scans.db` (a real lab run). `synthetisch` = `synth --hosts 2000 --seed 42`.
`40-vorher-*` / `40-nachher-*`: the same fixture scan 1 before (commit c49c756) and after the redesign.
- 01-login-dunkel-1280.png
- 01-login-hell-1280.png
- 01b-login-fehler-dunkel-1280.png
- 01b-login-fehler-hell-1280.png
- 02-dashboard-live-scan1-dunkel-1280.png
- 02-dashboard-live-scan1-dunkel-ganz.png
- 02-dashboard-live-scan1-hell-1280.png
- 02-dashboard-live-scan1-hell-ganz.png
- 03-heatmap-host-tooltip-jump-a2-dunkel-1280.png
- 03-heatmap-host-tooltip-jump-a2-hell-1280.png
- 04-heatmap-drawer-jump-a2-dunkel-1280.png
- 04-heatmap-drawer-jump-a2-hell-1280.png
- 05-host-a1-live-dunkel-1280.png
- 05-host-a1-live-hell-1280.png
- 06-host-c1-live-dunkel-1280.png
- 06-host-c1-live-hell-1280.png
- 07-key-k_dsa-live-dunkel-1280.png
- 07-key-k_dsa-live-hell-1280.png
- 08-findings-live-dunkel-1280.png
- 08-findings-live-hell-1280.png
- 09-keys-live-dunkel-1280.png
- 09-keys-live-hell-1280.png
- 10-hosts-live-dunkel-1280.png
- 10-hosts-live-hell-1280.png
- 11-crawl-tree-filter-c-live-dunkel-1280.png
- 11-crawl-tree-filter-c-live-hell-1280.png
- 12-graph-um-a1-live-dunkel-1280.png
- 12-graph-um-a1-live-hell-1280.png
- 13-scans-live-dunkel-1280.png
- 13-scans-live-hell-1280.png
- 14-fixture-scan2-host-c2-hostkey-changed-dunkel-1280.png
- 14-fixture-scan2-host-c2-hostkey-changed-hell-1280.png
- 15-fixture-diff-1-2-edges-dunkel-1280.png
- 15-fixture-diff-1-2-edges-hell-1280.png
- 16-fixture-diff-1-2-hosts-c2-geaendert-dunkel-1280.png
- 16-fixture-diff-1-2-hosts-c2-geaendert-hell-1280.png
- 20-dashboard-live-375-dunkel.png
- 20-dashboard-live-375-hell.png
- 21-findings-live-375-dunkel.png
- 21-findings-live-375-hell.png
- 22-host-a2-live-375-dunkel.png
- 22-host-a2-live-375-hell.png
- 23-findings-graustufen-fuenf-schweregrade.png
- 24-suche-legacy-dsa-zweizeilig.png
- 25-key-k_dsa-nach-suche-authorized-on.png
- 26-key-k_dsa-label-gespeichert.png
- 27-findings-gefiltert-key_unknown_origin-high.png
- 30-synthetisch-2000-subnet-heatmap-banner-1280.png
- 30b-synthetisch-2000-subnet-heatmap-banner-dunkel.png
- 31-synthetisch-crawl-filter-syn-1987.png
- 32-synthetisch-dashboard-banner.png
- 40-nachher-dashboard-hell.png
- 40-nachher-findings-hell.png
- 40-nachher-host-c1-hell.png
- 40-vorher-dashboard-hell.png
- 40-vorher-findings-hell.png
- 40-vorher-host-c1-hell.png
