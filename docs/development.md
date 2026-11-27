# Development: test lab, tests and CI

## Layout

| Path | Contents |
|---|---|
| `sshbite/` | The Python package: CLI, crawl, transport, collector scripts, parsers, derivation, DB, web API |
| `frontend/` | The UI: Svelte 5 + TypeScript + Vite. `npm run build` writes `sshbite/web/static/` |
| `lab/` | The test lab: 13 OpenSSH hosts (Debian 12) behind a jump host, plus the stand-alone AlmaLinux 9 host r1 (docker compose) |
| `tests/` | `unit/`, `web/` (HTTP API), `e2e/` (against the lab), `browser/` (Playwright) |
| `Dockerfile`, `compose.lab.yaml` | The image; `compose.lab.yaml` = the lab plus the image scanning it (lab demo only) |
| `.github/workflows/ci.yml` | CI |

## Set up

```sh
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install --no-deps -e .          # builds the frontend (needs Node 22)
```

`SSHBITE_SKIP_FRONTEND=1` skips the frontend build. During UI work: `cd frontend && npm ci && npm run dev`
(Vite proxies `/api` to `sshbite serve` on 127.0.0.1:8722).

Dependencies are pinned with hashes: `requirements.lock` (runtime and the `test` extra, for development
and CI), `requirements-runtime.lock` (runtime only, without pytest – what the image and a pip install for
real use get; the same versions) and `requirements-build.lock` (setuptools and wheel for the image's wheel
build), generated with
`uv pip compile … --generate-hashes --python-version 3.12` (the command is in each file's header).
npm uses `frontend/package-lock.json`.

## The test lab

`lab/` holds 13 real OpenSSH servers (Debian bookworm, OpenSSH 9.2) behind a jump host, seeded with
realistic legacy: cross-host keys, orphaned keys, DSA/RSA-1024, root keys, hashed known_hosts. All its
keys are test-only and committed (`lab/keys/README.md`).

```sh
lab/up.sh                     # docker compose (else podman, else as root: lab/local/up.sh); renders lab/sshbite.lab.yaml
.venv/bin/sshbite -c lab/sshbite.lab.yaml config validate --connect
SSHBITE_SUDO_PASSWORD=labsudo .venv/bin/sshbite -c lab/sshbite.lab.yaml scan
.venv/bin/sshbite -c lab/sshbite.lab.yaml scans show latest
docker compose -f lab/compose.yaml down        # remove the lab
```

- The jump host is published on `127.0.0.1:2222`. If the lab runs elsewhere, render the config with
  `LAB_NO_START=1 LAB_ENTRY_HOST=<host> LAB_ENTRY_PORT=<port> lab/up.sh` and point the e2e test at it with
  `SSHBITE_LAB_ENTRY=<host>:<port>`. The test needs to reach the lab addresses (172.30.1-4.0/24) directly.
- r1 (AlmaLinux 9, `lab/image/Dockerfile.el9`) sits alone on `lab_r` (172.30.4.11, published on
  `127.0.0.1:2223`) and is scanned directly by `tests/e2e/test_lab_installed.py` (i04, i06-i08); point the
  test at it with `SSHBITE_LAB_R1=<host>:<port>` if it answers elsewhere. No other lab host refers to it,
  so it is not part of `lab/expected.yaml`. `lab/local/up.sh` does not build r1.
- `lab/race.sh start|count N|stop` (run as root on a lab host through the lab control) sets up the
  symlink race of review.md for test i08.
- Without docker or podman, `lab/local/up.sh` (root) builds the same hosts with network, mount and PID
  namespaces; `lab/local/down.sh` removes them.
- `docker compose -f compose.lab.yaml up -d --build` at the top level starts the lab **and** the SSHBITE
  image (`lab/demo/start.sh`): it validates the entry, creates the UI user `admin` (password from
  `SSHBITE_DEMO_PASSWORD`, else a random one printed once in the log under `LAB DEMO LOGIN`; the old
  fixed demo password is refused), runs one scan with the lab's sudo password in `SSHBITE_SUDO_PASSWORD`
  and serves the UI on http://127.0.0.1:8722/.

## Tests

```sh
.venv/bin/python -m pytest tests/unit tests/web    # unit tests and the HTTP API, no lab needed
.venv/bin/python -m pytest tests/e2e               # spec 9.3 against the running lab (starts it if it can)
.venv/bin/pip install playwright==1.65.2 && .venv/bin/playwright install chromium
.venv/bin/python -m pytest tests/browser           # spec 9.4 browser checks (needs the built frontend)
```

- The e2e test snapshots `/etc`, `/root` and `/home` of every lab host before and after every scan
  (`lab/snapshot.sh`) and fails unless they are byte-identical. It changes the lab only between scans
  (`lab/labctl.sh`), through a separate lab-control sshd on port 2200 that lives outside `/etc/ssh`, and
  resets the lab at the end.
- `SSHBITE_EVIDENCE_DIR=<dir>` makes the e2e test keep console transcripts, exports and snapshot diffs.
- Lab expectations are hand-written in `lab/expected.yaml` (from spec 9.3).
- `tests/fixtures/lab_scans.db` holds scans 1–3 of a real lab run; the web and browser tests use it, so
  they need no running lab. Regenerate it with `pytest tests/e2e --basetemp=DIR` and copy
  `DIR/e2e0/sshbite.db`.
- After changing `sshbite/collector/collect.sh`, run `python tools/update_collector_sha.py` to update its
  `B=` line.

## CI

`.github/workflows/ci.yml` runs on every push to `main` and every pull request:

| Job | What it runs |
|---|---|
| `lint` | `ruff check .` (config in `pyproject.toml`), `npm run check` (svelte-check), the collector allowlist lint via `sshbite collector show`, `docker compose config` of both compose files |
| `unit` | `pytest tests/unit tests/web`; fails if anything was skipped |
| `e2e` | `lab/up.sh` (docker compose, 13 hosts + r1), `pytest tests/e2e/test_lab.py tests/e2e/test_lab_installed.py`; fails if skipped; uploads the transcripts |
| `browser` | Playwright + Chromium, `pytest tests/browser`; fails if skipped |
| `image` | `docker build`; checks uid 10001, `sshbite --version`, the lint inside the image; `docker compose up` of lab + image: the image validates the pinned entry, scans the lab (20 access edges) and serves the UI with its CSP; an unauthenticated write gets 401 |

To run the same steps locally, use the commands of each job's `run:` lines in that order;
[`act`](https://github.com/nektos/act) also runs the workflow if Docker is available.
