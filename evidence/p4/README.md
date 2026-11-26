# Evidence for the corrections package (check-6 web UI, check-7 security)

Produced from this branch. The company's compose stack ran the lab demo (`compose.lab.yaml`: 13 real OpenSSH
hosts + the SSHBITE image). This workspace reached the lab's network directly, so the lab e2e test ran live
against the same 13 hosts. No Docker in this workspace: the image was built and run only by the stack.

| Asked for | File |
|---|---|
| full pytest, lab e2e (scans 1–3, read-only snapshots around every scan) | `pytest-e2e.txt` (16 passed, none skipped), transcripts and empty snapshot diffs in `e2e/` |
| full pytest, unit + web API | `pytest-unit-web.txt` (213 passed, none skipped) |
| all Playwright checks | `pytest-browser.txt` (23 passed, among them the new `test_f1`…`test_f6`) |
| ruff, svelte-check, collector lint | `lint.txt` |
| `start.sh` without `SSHBITE_DEMO_PASSWORD`: random password printed once | `start-sh-random-password.txt` (the full container log of that start, scan 1 = spec 9.3) |
| `start.sh` with the old literal: refusal | `start-sh-old-password-refused.txt` |
| `pip list` from the runtime image | first lines of both `start-sh-*.txt` (the demo prints it): no pytest, pluggy, playwright |
| J1 lab demo in the browser: old password refused, random one works | `j1-lab-demo-login.txt`, screenshots `c7-j1-lab-demo-*` |
| J1 behind a TLS proxy: Secure cookie, per-IP limit per real client, bind rules | `j1-proxy-walk.txt` (script `proxy_walk.py`), screenshot `c7-j1-proxy-dashboard-over-https.png` |
| S3 live: password not sent outside `privilege.password_scope` | `cli-password-scope-live.txt` |
| S5 warning, S7 refusals, S3 literal commands | `cli-checks.txt` |
| the UI walk behind the screenshots | `ui-walk.txt` (script `tools/ui_evidence_corrections.py`) |

Unit tests added: `tests/unit/test_security_fixes.py` (S3 absolute sudo path and PATH independence, password
scope against an in-process SSH server with a fake sudo, S5 warning text, S7 non-TTY refusals, S8 CSV guard) and
`tests/web/test_security_web.py` (S2 Secure flag, trusted proxy last hop, untrusted peer, bind refusal,
`--insecure-bind` warning; S8 64 KiB limit incl. chunked bodies; F6a export file name).

## Screenshots (`/state/screens/`)

Scan 1: live lab scan of the stack's lab demo. Scans 2 and 3: the live e2e run of this package (its database,
served locally). Synthetic: `sshbite synth --hosts 2000 --seed 42` added as scan 4 to a copy of the lab fixture DB.

| Screen | File |
|---|---|
| c1 Host detail with both attempts | `c6-01-host-c1-route-attempts-1440.png`, `c6-01b-…-375-dark.png` |
| c2 in scan 2, Findings tab open | `c6-02-host-c2-scan2-findings-tab.png` |
| jump→a2 drawer at 1440 px | `c6-03-heatmap-drawer-jump-a2-1440.png` |
| Findings at 1280 px / 375 px | `c6-04-findings-1280.png`, `c6-05-findings-375-dark.png`, `c6-05b-…-scrolled-sideways.png` |
| /scans and Diff with a synthetic scan | `c6-06-scans-synthetic-scan-selected.png`, `c6-07-diff-real-vs-synthetic.png` |
| search popover, keyboard-selected result, after Enter | `c6-08-search-legacy-dsa-arrowdown-selected.png`, `c6-09-key-k_dsa-after-enter.png` |
| crawl tree, 2,000 synthetic hosts | `c6-10a-crawl-2000-expanded-top.png`, `c6-10-crawl-2000-scrolled-to-late-host.png` (row 3,958 of 3,970) |
| Accounts tab | `c6-11-host-a1-accounts-2-of-21.png` |
| Host detail with `?tab=bogus` | `c6-12-host-c1-tab-bogus-falls-back-to-overview.png` |
| Diff 1↔2 hosts: route removed | `c6-13-diff-1-2-hosts-route-removed.png` |
| crawl tree at 1280 px, c1's attempts open | `c6-14-crawl-tree-1280-c1-attempts-open.png` |
| filtered findings (export named `sshbite-scan1-findings-key_unknown_origin-high.csv`) | `c6-15-findings-key_unknown_origin-high-1440.png` |
