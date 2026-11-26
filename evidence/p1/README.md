# Evidence for package P1 (Foundation)

All files were produced from the committed code against the lab: 13 Docker containers with real
OpenSSH 9.2 (Debian bookworm) behind the jump host, started from `compose.yaml` → `lab/compose.yaml`.
The e2e test wrote the transcripts with `SSHBITE_EVIDENCE_DIR=evidence/p1`.

| # | Asked for | File |
|---|---|---|
| 1 | full pytest output, unit and e2e | `pytest.txt` |
| 2 | console transcript of `sshbite scan` (scan 1) | `console-scan1.txt` (scans 2 and 3: `console-scan2.txt`, `console-scan3.txt`; pin negative test: `console-pin-negative.txt`) |
| 3 | `sshbite scans show`, `sshbite diff 1 2`, findings CSV and access-edges CSV of scan 1 | `scans-show-1.txt`, `diff-1-2.txt` (+ `diff-1-2.json`), `scan1-findings.csv`, `scan1-access-edges.csv`; also `scan1-key_unknown_origin.csv` (J5 worklist), `scans-show-2.txt` (c2 host key changed), `scans-show-3.txt`, `scan3-hosts.csv` (J6 reasons and tried routes) |
| 4 | `sshbite collector show` | `collector-show.txt` |
| 5 | diff of the before/after snapshots (expected empty) | `snapshot-pin-negative.diff`, `snapshot-scan1.diff`, `snapshot-scan2.diff`, `snapshot-scan3.diff` (all empty); what a snapshot covers: `snapshot-scan1-before.txt`; that the snapshot detects changes: `snapshot-lab-changes-before-scan2.diff` (the test's own lab changes between scan 1 and scan 2) |
| 6 | runtime of `sshbite synth --hosts 2000 --seed 42`, including derivation | `synth-2000-seed42.txt` |

Further:
- `j1-install-and-configure.txt`: journey J1 on the command line (init-config, pin from ssh-keyscan,
  key file mode error, `config validate --connect`, a wrong pin, `user add`).
- `writecheck.txt`: `sshd -T` and `ssh-keygen -y/-l` on three lab hosts change nothing anywhere on the
  root filesystem (mtime, ctime, size, mode of every path except /proc, /sys, /dev, /run, /var/log).
