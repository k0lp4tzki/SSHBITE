# SSHBITE
Crawls and Visualizes SSH connections via Key Entries and creates a heatmap

SSHBITE is a **read-only SSH access audit** for Linux/OpenSSH estates – built for cleaning up after a
security incident. From one verified entry point (a jump host with a pinned host key) it crawls to every
host it can find and answers:

- **Who may connect from where to where** – every `authorized_keys` line, matched with the private keys
  found on other hosts, becomes an access edge (`jump:ops → a2:root`); keys whose private half was found
  nowhere are flagged as *unknown origin*.
- **Which systems hold a key** – where each public key is authorized (host, user, file:line, options),
  where its private half and `.pub` copies are, and which hosts know which in `known_hosts`.
- **Whether the cryptography is current** – ed25519 is good, RSA 2048 weak, RSA < 2048 and DSA critical
  (configurable), plus findings such as root keys, unencrypted or readable private keys, changed host
  keys and `PermitRootLogin yes`.

A web UI shows it centrally: a heatmap of inbound and outbound access, a connection graph, views per
host, key and user, findings with CSV/JSON export, and a diff between scans to confirm the cleanup.

SSHBITE changes nothing on the audited systems: it runs one fixed, reviewable shell script that only
reads (`sshbite collector show`), uses only its own audit key, and never uses keys it finds. It does
leave log entries and can trigger sudo mails and monitoring alerts – read
[docs/side-effects.md](docs/side-effects.md) before the first real scan. Everything stays local: one
SQLite database, a UI on `127.0.0.1` behind a login, no external services or CDNs.

## Quick start (Docker)

1. **Build the image** in this repository: `docker build -t sshbite:0.1.0 .`
2. **Create the audit key and deploy it** for an account `sshbite` with sudo on every host
   ([install.md](docs/install.md#the-audit-key-and-account)):
   `install -d -m 700 /etc/sshbite && ssh-keygen -t ed25519 -N '' -f /etc/sshbite/audit_ed25519`
3. **Write the config** with your entry host and its pinned host key
   ([install.md](docs/install.md#pin-the-entry-host-key)), then give both files to the container user:
   ```sh
   docker run --rm sshbite:0.1.0 sshbite init-config > /etc/sshbite/sshbite.yaml   # edit entry, set database: /data/sshbite.db
   chown -R 10001:10001 /etc/sshbite && chmod 600 /etc/sshbite/*
   ```
4. **Start it and check the entry**:
   ```sh
   docker compose -f docs/compose.example.yaml up -d
   docker exec -it sshbite sshbite config validate --connect    # entry OK, pinned key matches, sudo: root
   docker exec -it sshbite sshbite user add admin
   ```
5. **Scan and look**: `docker exec -it sshbite sshbite scan --ask-sudo-password`, then open
   http://127.0.0.1:8722/ and log in.

Without Docker: `pip install` (Python 3.12) – see [install.md](docs/install.md#install-with-pip).
To try SSHBITE without real systems, `docker compose up -d --build` starts a test lab of 13 OpenSSH hosts
plus SSHBITE scanning it (UI on http://127.0.0.1:8722/, login `admin` / `sshbite-lab-demo`).

## Documentation

| | |
|---|---|
| [Install](docs/install.md) | pip and Docker; audit key, account and sudoers; pinning the entry host key |
| [Configuration](docs/configuration.md) | every config key with its default and meaning |
| [Running scans](docs/scanning.md) | crawl, scope, seeds, `--ask-sudo-password`, host statuses, exit codes |
| [Operations](docs/operations.md) | systemd units for the UI and a nightly scan, backup, update |
| [Cleanup workflow](docs/cleanup.md) | findings → worklist → remove → rescan → diff |
| [Read-only review](docs/review.md) | what is sent to targets and what the allowlist lint guarantees |
| [Side effects](docs/side-effects.md) | logs, sudo "incident" mails, access times, monitoring alerts |
| [Development](docs/development.md) | test lab, tests, CI |

## Commands

```
sshbite init-config | config validate [--connect]
sshbite scan [--max-depth N] [--max-hosts N] [--concurrency N] [--timeout S] [--no-crawl]
             [--ask-sudo-password] [--label TEXT] [--dry-run]
sshbite scans list|show ID|delete ID       sshbite diff A B
sshbite export --what findings|keys|edges|hosts|authorized [--format csv|json] [-o FILE] ...
sshbite hostkey list|accept ADDR[:PORT]|forget ADDR
sshbite user add|passwd|remove NAME        sshbite serve [--bind --port --tls-cert --tls-key]
sshbite db backup PATH                     sshbite collector show        sshbite synth
```

Exit codes: 0 scan done (also with partial or unreachable hosts), 2 config error, 3 entry failure
(unreachable, pin missing or mismatch, authentication failed), 4 internal error, 5 another scan is running.
