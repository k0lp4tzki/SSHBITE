# SSHBITE
Crawls and Visualizes SSH connections via Key Entries and creates a heatmap

SSHBITE is a read-only SSH access audit: it starts at one verified entry point (pinned host key),
crawls breadth-first to every reachable Linux/OpenSSH host, and records who may connect from where to
where with which key. Results go to one SQLite database; `sshbite --help` lists the commands.

## Test lab and tests

The lab (`lab/`) is 13 real OpenSSH servers (Debian bookworm, OpenSSH 9.2) behind a jump host, seeded
with realistic legacy: cross-host keys, orphaned keys, DSA/RSA-1024, root keys, hashed known_hosts.
All its keys are test-only and committed (`lab/keys/README.md`).

```sh
python3.12 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements.lock && .venv/bin/pip install --no-deps -e .

lab/up.sh                     # docker compose (else podman, else as root: lab/local/up.sh); renders lab/sshbite.lab.yaml
.venv/bin/sshbite -c lab/sshbite.lab.yaml config validate --connect
SSHBITE_SUDO_PASSWORD=labsudo .venv/bin/sshbite -c lab/sshbite.lab.yaml scan
.venv/bin/sshbite -c lab/sshbite.lab.yaml scans show latest

.venv/bin/python -m pytest tests/unit          # unit tests, no lab needed
.venv/bin/python -m pytest tests/e2e           # spec 9.3 against the running lab (starts it if it can)
docker compose -f lab/compose.yaml down        # remove the lab
```

- The jump host is published on `127.0.0.1:2222`. If the lab runs elsewhere, render the config with
  `LAB_NO_START=1 LAB_ENTRY_HOST=<host> LAB_ENTRY_PORT=<port> lab/up.sh` and point the e2e test at it with
  `SSHBITE_LAB_ENTRY=<host>:<port>`. The test needs to reach the lab addresses (172.30.1-3.0/24) directly.
- The e2e test snapshots `/etc`, `/root` and `/home` of every lab host before and after every scan
  (`lab/snapshot.sh`) and fails unless they are byte-identical. It changes the lab only between scans
  (`lab/labctl.sh`), through a separate lab-control sshd on port 2200 that lives outside `/etc/ssh`.
- `SSHBITE_EVIDENCE_DIR=<dir>` makes the e2e test keep console transcripts, exports and snapshot diffs.
- `compose.yaml` at the top level only includes `lab/compose.yaml`.
- Without docker or podman, `lab/local/up.sh` (root) builds the same hosts with network, mount and PID
  namespaces; `lab/local/down.sh` removes them.
- Lab expectations are hand-written in `lab/expected.yaml` (from spec 9.3).
