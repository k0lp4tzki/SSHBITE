# Evidence: privilege.mode installed, collector export and gate (order A-ef5350a11f, package A)

All runs against the company's compose lab (`compose.yaml` → `lab/compose.yaml`, 13 Debian 12 hosts with
OpenSSH 9.2 and sudo 1.9.13p3), started fresh (`stack up --fresh`) from this branch; this workspace reaches
the lab network directly (`SSHBITE_LAB_ENTRY=jump:22`). No Docker in the workspace.

## Test runs

| What | File | Result |
|---|---|---|
| `pytest tests/unit tests/web -v -rs` (frontend built, nothing skipped) | `pytest-unit-web.txt` | 262 passed |
| `pytest -m e2e tests/e2e/test_lab.py tests/e2e/test_lab_installed.py -v -rs` | `pytest-e2e.txt` | 23 passed, none skipped |
| Transcripts written by that e2e run (`SSHBITE_EVIDENCE_DIR`) | `e2e/` | see below |

## The files the CEO asked for

| Item | File |
|---|---|
| `sshbite collector export` output | `e2e/console-export.txt`, `walk.txt` (J1, J3) |
| `sha256sum -c SHA256SUMS` | `e2e/console-sha256sum-c.txt`, `walk.txt` |
| `config validate --connect`, success | `e2e/console-validate-ok.txt` |
| `config validate --connect`, failure (collector_path the gate does not allow → exit 3) | `e2e/console-validate-failed.txt`; version mismatch → exit 3 in `walk.txt` (J3) |
| Attack matrix of i04 (request, exit, first stderr line) | `e2e/attack-matrix.md` |
| Diff baseline (mode sudo) → installed | `e2e/diff-baseline-installed.txt` (the deviations are explained in the note to the CEO) |
| Scans: baseline, installed, broken installations | `e2e/console-scan-*.txt`, `e2e/scans-show-installed.txt`, `e2e/scans-show-failures.txt` |
| Read-only brackets of every scan (all empty) | `e2e/snapshot-*.diff` |
| Lab hosts after `installed.sh remove` byte for byte as before `apply` | `e2e/snapshot-before-apply-vs-after-remove.diff` (empty) |
| Real sudo stderr per failure case and the resulting message | `sudo-stderr.md` (made by `sudo_stderr.py`) |
| Journeys J1–J4 walked with the CLI | `walk.txt` (made by `walk.py`) |
| UI after the installed scans, desktop 1440 px and phone 390 px | `screens/` (made by `screens.py`) |

## Screens

| File | Shows |
|---|---|
| `01-hostliste-installed-ok-root-{desktop,handy}.png` | Scan "J1 installed": every collected host `OK` / `root` |
| `02-host-a4-collector-error-sudoers-fehlt-{desktop,handy}.png` | Full crawl with a4's sudoers file removed: a4 `Collector error` with the message |
| `03-hostliste-kaputte-installationen-{desktop,handy}.png` | Scan of the five broken installations: all `Collector error`, none partial |
| `04-host-a5-collector-error-version-{desktop,handy}.png` | a5 with an old collector: the version message |
| `05-host-b2-collector-error-keine-regel-{desktop,handy}.png` | b2 with a sudo rule for something else: "sudo does not allow …" |
