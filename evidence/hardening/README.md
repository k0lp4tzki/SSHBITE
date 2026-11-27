# Evidence: privilege.mode installed, collector export, gate (package A) and reading user homes as their owner (package B)

Order A-ef5350a11f. The test runs below are package B's and replace package A's: same lab plus the AlmaLinux 9
host r1 (`lab/image/Dockerfile.el9`: AlmaLinux 9.9, OpenSSH 9.9p1, sudo 1.9.17p2, util-linux 2.37.4), started
fresh (`stack up --fresh`) from the branch; r1 answered as `r1:22` (`SSHBITE_LAB_R1` not needed).

All runs against the company's compose lab (`compose.yaml` → `lab/compose.yaml`, 13 Debian 12 hosts with
OpenSSH 9.2 and sudo 1.9.13p3), started fresh (`stack up --fresh`) from this branch; this workspace reaches
the lab network directly (`SSHBITE_LAB_ENTRY=jump:22`). No Docker in the workspace.

## Check-4 package (findings 1–6 of the security review): what changed

All runs below are from this package (lab started fresh with `stack up --fresh` from commit 6c531a9). Collector
hash now **B=386f9faea780**; `lab/expected.yaml` unchanged (`test_lab.py::test_08` green, `private_key_unencrypted`
still 7).

| Finding | What changed | Evidence |
|---|---|---|
| 1 FIFO race hangs the root collector | `collect.sh`: every read as the account is `timeout -k 1 5 setpriv …` (`uls`, `ustat`, `ulsnd`, `uread` (was `uhead`), `utest`, `ukg`); `test -f` as the account right before every read; a read that times out is `#X PATH<TAB>read timed out` and the run goes on; after 2 timeouts in one account the rest of it is skipped (`time budget exceeded`, host `partial`). Without `timeout` as root nothing in homes is read (`#V timeout no`, host `partial`). Gate: `exec "$TIMEOUT" -k 5 3600 "$SUDO" -n P` (3600 s = the largest `limits.host_timeout`; sudo passes TERM on to the collector – tried on jump and r1). Lint: `setpriv` only behind exactly `timeout -k 1 5`. | `e2e/race-count-fifo.md` (i09: r1 and a5, 200 runs each through the gate, 0 hangs, 200/200 `#END` within 30 s, 3 `read timed out` each, no root process left; control blocked 41/200 and 46/200); `test_hostile.py::test_fifo_swapped_in…`, `…given_up_after_two_timeouts`; `test_lint.py` |
| 2 output flood cuts later accounts | 1 MiB per file (unchanged limit, now on the bytes read), 4 MiB per account, then `#X <home>/.ssh<TAB>output budget exceeded` and the next account; `AuthorizedKeysFile` files of an account are read first. Crawl: host `partial`, reason `output budget exceeded: <home>/.ssh`. UI: strip "Inventory incomplete – data of this host is missing" for this and `output_limit`. | i10 (`e2e/scans-show-installed-flood.txt`: a5 `partial`, reason, zvictim's key stored); `test_hostile.py::test_flood…`, `test_scan_offline.py::test_flood_account_is_partial…`; screens 12–14 |
| 3 remote forwarding on A and C | `permitlisten="localhost:22"` in variants A and C (template, `tests/e2e/lab.py`, guard in `lab/installed.sh`). `permitlisten="none"` is **not** accepted in authorized_keys by OpenSSH 9.2 or 9.9 (sshd rejects the whole key line – tried); `127.0.0.1:1` (check-4) still opened a listener on port 1 in the lab. | `e2e/attack-matrix.md` (i04: every `tcpip-forward` refused on jump, a1, r1; `-L` to 22 opened); `walk-c4.txt` J3 |
| 3 (residual) | A listener on a **Unix socket** (`streamlocal-forward`) is not covered by permitlisten: it opens on jump and r1 (mode 0600, sshbite). install.md gives the `Match User sshbite` block (`AllowTcpForwarding local`, `AllowStreamLocalForwarding no`); tried on jump and r1: refused, `-L` 22 and the collector still work. | `e2e/attack-matrix.md` rows `streamlocal-forward` |
| 4 ssh-keygen as root on user bytes | The 0644 case no longer pipes into root's ssh-keygen. It runs `timeout -k 1 5 setpriv --ruid="$nbd" --euid="$uid" --regid="$gid" --clear-groups --no-new-privs -- ssh-keygen -y -P '' -f PATH` (real uid nobody, effective uid the owner, no caps). The brief's form (`… | setpriv … ssh-keygen -f /dev/stdin`) does not work: the account may not reopen root's pipe (`Permission denied`, tried on Debian 12 and AlmaLinux 9). Lint refuses ssh-keygen on stdin altogether. | `test_hostile.py::test_owners_0644…` (no ssh-keygen as root, none on stdin); i03/`test_08` (`private_key_unencrypted` 7) |
| 5 gate waits for logger | `log()` runs `"$TIMEOUT" -k 1 2 logger … </dev/null >/dev/null 2>&1 \|\| :` (plain `logger` where timeout is missing). | `test_gate.py::test_gate_does_not_wait_for_a_hanging_logger` (copy of the gate with a fake `logger` = `sleep 30` first in PATH: 126 in ~2 s) |
| 6 existing account sshbite | install.md: `usermod -s /bin/sh sshbite`, section "An account sshbite that existed before" (shell, groups, `ls -la`, `.ssh` only `authorized_keys`, cron/processes, `sshd -T` with expected output). | `walk-c4.txt` J4 on r1: before, a former admin's key in `authorized_keys2` logged in to bash with `(root) NOPASSWD: ALL` via wheel; the install block's `sudo -l -U sshbite` check stopped; after the steps the key is refused and sudo lists only the collector |

New UI screens (`screens/`, made by `walk_c4.py screens`):

| Screen | Shows |
|---|---|
| `10-hostliste-installed-ok-root-{desktop,handy}.png` | Scan "installed": every collected host `OK` / `root` |
| `11-host-a5-fifo-race-read-timed-out-{desktop,handy}.png` | a5 during the FIFO race: `OK`, info strip `read timed out: /home/racer/.ssh/known_hosts` |
| `12-hostliste-a5-flood-partial-{desktop,handy}.png` | Scan "a5 flood": a5 `Partial`, all others `OK` |
| `13-host-a5-output-budget-exceeded-{desktop,handy}.png` | a5: "Inventory incomplete – data of this host is missing: output budget exceeded: /home/racer/.ssh" |
| `14-host-a5-flood-users-zvictim-{desktop,handy}.png` | a5 Users: zvictim (after racer in passwd) with its key `VICTIMBACKDOOR` |

`walk-c4.txt` (made by `walk_c4.py`) is the CLI walk of the four journeys. `pytest tests/browser` after the
HostDetail change: 35 passed (not kept as a file).

## Test runs

| What | File | Result |
|---|---|---|
| `pytest tests/unit tests/web -v -rs` (frontend built, nothing skipped) | `pytest-unit-web.txt` | 346 passed |
| `pytest -m e2e tests/e2e/test_lab.py tests/e2e/test_lab_installed.py -v -rs` (13 hosts + r1) | `pytest-e2e.txt` | 28 passed, none skipped |
| Lint run (ruff, svelte-check, `collector show` → `lint: OK` for both scripts, `test_lint.py`) | `lint.txt` | see file; the 7 ruff findings are in `evidence/p6/` and `tools/rechte-doc/` (pre-existing, untouched) |
| `pytest tests/browser` (after the HostDetail change) | – (not kept) | 35 passed |
| Transcripts written by that e2e run (`SSHBITE_EVIDENCE_DIR`) | `e2e/` | see below |

## Correction 1 (CEO): what changed in these files

- `collect.sh`: an owner's group/other-readable private key (a1 deploy's 0644 `id_rsa`) is found
  *unencrypted* again. When `ssh-keygen -y` run as the account says "bad permissions" / "UNPROTECTED
  PRIVATE KEY FILE", the account reads the key (`uhead`) and the collector's own ssh-keygen gets it on a
  pipe: `uhead 5000 PATH 2>/dev/null | head -c 65536 | ssh-keygen -y -P '' -f /dev/stdin`. No path below
  `~` is opened as root. The lint allows `-f /dev/stdin` only in this one pipeline (`test_lint.py::setpriv_keygen_stdin_*`);
  `test_hostile.py::test_owners_0644_private_key_is_still_found_unencrypted` runs collect.sh with it.
- `lab/expected.yaml` is again byte for byte package A's (`private_key_unencrypted: 7`); `test_lab.py::test_08` checks it.
- A name that `ls -A` listed but that is gone before it is read is now `vanished while reading`
  (was wrongly `name with tab or newline skipped`); `e2e/race-count.md` shows it under that name.
- Hash B is new; `pytest-unit-web.txt`, `pytest-e2e.txt`, `lint.txt` and every file in `e2e/` are from
  the runs after the correction (lab started fresh from this branch). The screens did not change and were
  not taken again; `walk.txt` and `walk-r1.txt` (CLI walks) are also from before the correction and show
  the old B=2d534dece3d8.

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

## Package B: files in user homes read as their owner (R3, R4)

| Item | File |
|---|---|
| Race count per host (control n/200 as root, collector 0/200 through the gate, runs in the window) | `e2e/race-count.md` (i08) |
| Attack matrix incl. r1 (AlmaLinux 9, variant A) | `e2e/attack-matrix.md` |
| sudo stderr on r1 (EL9) next to Debian; mapping to the spec 4.3 texts identical | `sudo-stderr.md` (made by `sudo_stderr.py`) |
| r1 installed scan: ok/root, `unreadable by account: /home/alice/.ssh/authorized_keys2` | `e2e/console-scan-r1-installed.txt`, `e2e/scans-show-r1-installed.txt`, `walk-r1.txt` |
| r1 without setpriv (J5): partial, `setpriv (util-linux) missing: files in user homes not read` | `e2e/console-scan-r1-no-setpriv.txt`, `e2e/scans-show-r1-no-setpriv.txt`, `walk-r1.txt` |
| CLI walk on r1 and the UI screenshots | `walk-r1.txt`, screens below (made by `walk_r1.py`) |

| Screen | Shows |
|---|---|
| `06-hostliste-r1-installed-ok-root-{desktop,handy}.png` | Scan "r1 installed": r1 `OK` / `root` (172.30.1.5 = jump from alice's known_hosts, depth limit of `--no-crawl`) |
| `07-host-r1-ok-root-unreadable-by-account-{desktop,handy}.png` | r1 OK/root with the info strip `unreadable by account: /home/alice/.ssh/authorized_keys2` |
| `07b-host-r1-users-alice-schluessel-{desktop,handy}.png` | r1 Users tab: alice's authorized key (k_ops), private key id_ed25519 (fingerprint, not encrypted), known_hosts - nothing from authorized_keys2 |
| `08-hostliste-r1-ohne-setpriv-partial-{desktop,handy}.png` | Scan "r1 without setpriv": r1 `Partial` / `root` |
| `09-host-r1-partial-setpriv-fehlt-{desktop,handy}.png` | r1 partial with the setpriv reason and the advice to install util-linux; Users (0) |
