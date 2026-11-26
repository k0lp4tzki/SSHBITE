# Evidence for package P2 (Web UI)

Produced from the committed code. Screenshots: `tools/ui_evidence.py evidence/p2 --running-scan-config
lab/sshbite.lab.yaml` (1440×900 unless the name says otherwise) against the real app on three databases:

- **lab data** – `tests/fixtures/lab_scans.db`, scans 1–3 of a real P1 lab run (13 OpenSSH containers, real sshd),
  identical in every number to spec 9.3;
- **synthetic** – `sshbite synth --hosts 2000 --seed 42` (every screen carries the SYNTHETIC DATA banner);
- **empty** – a fresh database with one UI user.

`15-*` comes from a real `sshbite scan` against the running lab while the dashboard was open (scan 4 in a copy
of the lab DB; its console is `15-running-scan-console.txt`).

| Asked for | File |
|---|---|
| every screen, dark, lab data | `02-dashboard-*`, `03-heatmap-*`, `04-graph-*`, `05-hosts*`, `06-host-*`, `07-keys`, `08-key-*`, `09-findings-*`, `10-crawl-tree`, `11-scans-two-selected`, `12-diff-1-2-*`, `13-search-*`, `01-login*` |
| light theme: Dashboard, Heatmap, Host detail (+ findings, graph) | `20-light-*` |
| heatmap by host, tooltip on jump→a2; the edge drawer | `03-heatmap-host-tooltip-jump-a2`, `03-heatmap-host-drawer-jump-a2` (also `checks/03-*`) |
| drill-down from a subnet cell at 2,000 hosts | `30-synth-heatmap-subnet-2000`, `30-synth-heatmap-tooltip-top-pairs`, `30-synth-heatmap-drilldown-subnet-cell`, `30-synth-heatmap-drilldown-hover`, `30-synth-heatmap-top-100x100` |
| graph around jump and around K_DSA | `04-graph-around-jump`, `04-graph-around-jump-2hops-both`, `04-graph-around-k_dsa` |
| Host detail a1, c1 (route jump→b3→c1), b5 (partial), 172.30.1.99 (routes tried) | `06-host-a1*`, `06-host-c1*`, `06-host-b5`, `06-host-172.30.1.99`; also c2 host key changed in scan 2 `06-host-c2-scan2-host-key-changed`, b3 Known by (stale) `06-host-b3-known_by`, a4 partial in scan 3 |
| Key detail K_FLEET | `08-key-k_fleet`, `08-key-k_fleet-private-half`; K_DSA with its label after reload `08-key-k_dsa-label-after-reload` |
| Findings filtered to key_unknown_origin | `09-findings-key_unknown_origin-high` |
| Diff of scans 1 and 2 | `12-diff-1-2-{hosts,keys,placements,edges,findings}` |
| login error and lockout | `01-login-error`, `01-login-lockout`, `01-login-session-ended` |
| empty-DB dashboard | `50-empty-dashboard`, `50-empty-scans` |
| 1280×800 and 375 px | `40-heatmap-1280x800`, `40-host-a1-users-1280x800`, `41-dashboard-375`, `41-host-c1-375`, `41-heatmap-375` |
| running scan, live progress, completion toast | `15-dashboard-running-scan-progress`, `15-dashboard-scan-completed-toast`, `15-dashboard-scan4-after-live-scan` |
| loading and error states | `14-state-loading-heatmap`, `14-state-loading-hosts-skeleton`, `14-state-error-findings` |
| pytest output | `pytest.txt` (unit + web API, 175 tests) |
| Playwright output | `playwright.txt` (spec 9.4 checks 1–10 + design checklist 3, 4, 5, 12, 13); `checks/` holds the screenshots the checks took, the greyscale shots (item 4) and the computed contrast tables `contrast-light.txt` / `contrast-dark.txt` (item 3) |
