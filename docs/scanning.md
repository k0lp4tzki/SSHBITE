# Running scans

```sh
sshbite scan [--max-depth N] [--max-hosts N] [--concurrency N] [--timeout S] [--no-crawl]
             [--ask-sudo-password] [--label TEXT] [--dry-run]
```

With Docker, prefix every command with `docker exec -it sshbite` (e.g.
`docker exec -it sshbite sshbite scan --ask-sudo-password`).

## What a scan does

1. **Connects to the entry host** and checks its host key against `entry.host_keys`. A missing or
   different key aborts the scan (exit 3) before anything is sent.
2. **Collects** the entry host: it runs the fixed, read-only collector script (`sshbite collector show`),
   with sudo if possible, and reads local accounts, `authorized_keys` with their options, the keys in
   `~/.ssh`, `known_hosts`, ssh client configs and the effective `sshd` settings. Private keys never
   leave the host – only their fingerprint, type, size and whether they are encrypted.
3. **Crawls** breadth-first, depth by depth. The next hosts come from what the current depth contains:
   - `known_hosts` entries (plain, and hashed ones matched against every name and address known in
     the scan),
   - `HostName`, `Host` (without wildcards) and `ProxyJump` in ssh configs,
   - literal names/addresses in `from="…"` of `authorized_keys`.
   Names are resolved on the entry host. Each reference is classified: `queued` (will be scanned),
   `alias` / `already` (known host), `excluded`, `out_of_scope`, `max_depth`, `max_hosts`,
   `unresolvable`. Only `queued` hosts are connected to.
4. **Reaches every host through the entry host** (an SSH tunnel opened on the entry host, no ssh client
   runs there). If that fails with a network error and `crawl.chain_fallback` is on, it tries the path
   the host was discovered on, e.g. entry → b3 → c1, checking the host key on every hop.
5. **Derives** access edges (who can log in where, with which key), evidence edges (known_hosts, ssh
   config), findings and the heatmap metrics, and stores the scan.

The console shows progress per depth and a summary:

```
scan: entry 172.30.1.5:22, max depth 10, max hosts 1000, concurrency 20
depth 0: 0 queued, 0 running, 1 done
...
depth 3: 0 queued, 0 running, 12 done (1 partial, 1 unreachable)

scan 1 completed in 14 s
hosts:    13 connected; 11 ok, 1 partial, 1 unreachable, 1 excluded, 2 out_of_scope, 1 unresolvable
findings: 37 - 4 critical, 15 high, 15 medium, 2 low, 1 info
edges:    20 access (19 effective, 3 unknown origin); keys: 10
scan id:  1
UI:       http://127.0.0.1:8722/  (start it with `sshbite serve`)
```

Only one scan runs at a time (a second one exits with code 5). The UI can stay open during a scan; it
shows the progress and picks up the new scan when it is done.

## Before the first real scan

- Read [side-effects.md](side-effects.md) and tell the people who receive sudo mails, watch the auth
  logs, or run IDS/EDR, that an audit crawl is coming and from which address.
- `sshbite scan --dry-run` prints the entry host, the audit account, the scope and every seed without
  connecting.
- `sshbite config validate --connect` checks the pin and sudo on the entry host.
- Consider `--max-depth 1` first to see what the entry host leads to.

## Scope: crawl, include, exclude

The normal case is the crawl from the entry host alone – no host list needed. Limit it with:

| Setting | CLI | Effect |
|---|---|---|
| `crawl.max_depth` (10) | `--max-depth N` | Hosts further away are listed as `max_depth`. |
| `crawl.max_hosts` (1000) | `--max-hosts N` | More hosts are listed as `max_hosts`. |
| `crawl.include` | – | If set, only matching hosts (CIDR or name glob) are scanned; others are `out_of_scope`. If empty, `config validate` and `scan` warn (below). |
| `crawl.exclude` | – | Matching hosts are never connected to, only listed as `excluded`. Exclude wins over include and over seeds. |
| – | `--no-crawl` | Scan only the entry host and the seeds. |

Without `crawl.include` the crawl goes wherever the targets' own files point: addresses **and ports** come
from known_hosts, `~/.ssh/config` and `from=` options of the scanned hosts. That is the default the owner
asked for, but after an incident those files may have been planted, so `config validate` and every `scan`
print:

```
warning: crawl.include is empty: crawl targets and ports are taken from target data (known_hosts, ~/.ssh/config, from=) without restriction; set crawl.include to the networks and host names you mean to scan
```

Set `crawl.include` to your networks and host name patterns to limit the crawl to them.

Every reference is kept, whether scanned or not: the crawl tree in the UI (Scans → crawl tree) and
`sshbite scans show ID` list each host with depth, the file and line it was discovered in, and its route.

## Seeds

Seeds are extra hosts at depth 0, next to the entry host (see
[configuration.md](configuration.md#seeds)):

```yaml
seeds:
  hosts_file: /etc/sshbite/extra-hosts      # "host", "host:port" or "[host]:port" per line
  cidrs: [10.20.0.0/24]                     # each address TCP-probed from the entry host first
  ansible_inventories: [/etc/sshbite/inventory.ini]
```

Seeds are crawled from like any other host. CIDR addresses that do not answer on the SSH port within
2 s get status `no_ssh`. Seed files are inside `/etc/sshbite` in the Docker setup, so the container can
read them.

## Sudo passwords

With `NOPASSWD` sudo nothing is needed. If sudo asks for a password:

```sh
sshbite scan --ask-sudo-password             # prompts once, without echo
docker exec -it sshbite sshbite scan --ask-sudo-password
```

`--ask-sudo-password` needs a terminal: without one (a pipe, `docker exec -i` without `-t`) it refuses,
because the password could be echoed. Non-interactively, e.g. from a timer, `SSHBITE_SUDO_PASSWORD=… sshbite
scan` works but is **not recommended** – the value is visible in `/proc/<pid>/environ` and, if passed to a
container, in `docker inspect` (see [operations.md](operations.md#the-sudo-password)). The same password is
tried on every host that asks for one, unless `privilege.password_scope` limits it to some hosts.
A compromised host can imitate a sudo prompt and capture the password: use one that only the audit account
has, and rotate it after the scan. It is kept
in memory for the scan only, removed from the environment, redacted from logs, and never written to the
database. A host where sudo is refused or the password is wrong is scanned unprivileged and marked
`partial`, with the reason (e.g. `sudo: a password is required`). If hosts needed a password and none was
given, the summary says:

```
2 hosts need a sudo password: rerun with --ask-sudo-password
```

Note that a wrong password counts as a failed sudo attempt on each host (see
[side-effects.md](side-effects.md)).

## Host statuses

| Status | Meaning |
|---|---|
| `ok` | Collected completely. |
| `partial` | Collected without root, or with unreadable parts; the reasons are listed on the host. |
| `output_limit` | More output than `limits.max_output_mb`; what was read is kept (counts as partial). |
| `collector_error` | The collector did not finish (no end marker). |
| `unreachable` | No route worked; every route tried and its error are listed on the host. |
| `timeout` | `limits.host_timeout` exceeded. |
| `auth_failed` | The audit key was not accepted (account or key not deployed). |
| `hostkey_mismatch` | The host key changed since it was first stored – critical finding `host_key_changed`; the host is not logged in to. |
| `hostkey_unknown` | Strict mode: the key is not in `hostkeys.known_hosts_file`. |
| `excluded`, `out_of_scope`, `max_depth`, `max_hosts`, `unresolvable`, `alias`, `no_ssh` | Seen but never connected to. |

**A host key changed.** Check the new key out of band (console), then trust it and rescan:

```sh
sshbite hostkey list
sshbite hostkey accept 10.1.2.3          # or ADDR:PORT
sshbite hostkey forget 10.1.2.3          # drop all stored keys; the next scan trusts what it sees
```

**Many hosts `unreachable` with "channel open failed".** The entry host refuses tunnels for the audit
account: remove `restrict`/`no-port-forwarding` from its `authorized_keys` line there, or allow
`AllowTcpForwarding` (see [install.md](install.md#the-audit-key-and-account)).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan done – also when some hosts were partial or unreachable. |
| 2 | Config error (schema, file modes, missing files). |
| 3 | Entry failure: unreachable, pin missing or mismatch, authentication failed. Only a failed/aborted scan row is written. |
| 4 | Internal error. |
| 5 | Another scan is running. |

## After the scan

```sh
sshbite scans list                         # all scans
sshbite scans show latest                  # hosts, depth, discovered via, route, reasons
sshbite export --what findings --format csv -o findings.csv
sshbite diff 3 4                           # what is new, gone or changed
sshbite scans delete 2
```

`export --what` is one of `findings`, `keys`, `edges`, `hosts`, `authorized`; filters are
`--min-severity`, `--rule` (repeatable), `--host GLOB` and `--kind access|evidence`. Most list commands
take `--json`.

The UI (`sshbite serve`) shows the same data: dashboard, heatmap, graph, hosts, keys, findings and diff.
For testing the UI at scale, `sshbite synth --hosts 2000 --seed 42` creates a synthetic scan; it is
marked SYNTHETIC DATA everywhere.

Next: the cleanup workflow in [cleanup.md](cleanup.md).
