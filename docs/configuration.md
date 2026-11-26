# Configuration reference

SSHBITE reads one YAML file: the path from `-c PATH`, else `$SSHBITE_CONFIG`, else
`/etc/sshbite/sshbite.yaml` (in the Docker image `SSHBITE_CONFIG=/etc/sshbite/sshbite.yaml`).
`sshbite init-config` prints an example with every key. Only `entry.host` and `entry.host_keys` have no
usable default.

- Unknown keys are errors. Errors name their path, e.g.
  `sshbite.yaml: crawl.include[2]: not a CIDR or glob`.
- Relative file paths (`database`, `audit.key_file`, `seeds.*`, `hostkeys.known_hosts_file`) are relative
  to the directory of the config file; `~` is expanded.
- Check a config with `sshbite config validate` (add `--connect` to test the entry host too). Exit code 2
  means a config error.
- Keep the file mode 0600: `config validate` warns when the config or the database is group- or
  world-readable.

## Complete example with the defaults

```yaml
database: /var/lib/sshbite/sshbite.db
entry:
  host: jump01.corp.example     # as reachable from the SSHBITE machine
  port: 22
  host_keys: ["ssh-ed25519 AAAAC3Nza..."]   # required; any match = verified
audit:
  user: sshbite
  key_file: /etc/sshbite/audit_ed25519      # must be 0600
  key_passphrase_env: null
privilege:
  mode: sudo        # sudo: sudo -n /bin/sh -s | sudo-login: sudo -n -i /bin/sh -s | none
crawl:
  max_depth: 10
  max_hosts: 1000
  include: []       # CIDRs / hostname globs; empty = no restriction
  exclude: []       # always wins
  chain_fallback: true
  hash_probe_include_cidrs: true
  hash_probe_max_addresses: 4096
  ssh_port: 22
seeds:              # optional extra seeds, depth 0
  hosts_file: null              # host or host:port per line, '#' comments
  cidrs: []                     # every address probed via the entry; total <= 65536
  ansible_inventories: []       # static INI or YAML
hostkeys:
  mode: tofu                    # tofu | strict
  known_hosts_file: null        # required if strict
limits:
  concurrency: 20
  host_timeout: 30              # whole host: connect + auth + sudo probe + collect
  connect_timeout: 10           # per hop
  entry_connections: 4          # tunnels multiplexed over these
  max_output_mb: 32
rules:
  strength:                     # first match wins
    good:     [ssh-ed25519, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com]
    ok:       [ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, "ssh-rsa>=3072"]
    weak:     ["ssh-rsa>=2048"]
    critical: ["ssh-rsa<2048", ssh-dss]
  many_hosts_threshold: 10
  ignore_audit_key: true
grouping:
  tags: [{name: dmz, match: ["10.1.0.0/16", "web-*"]}]   # first match wins, else "untagged"
web: {bind: 127.0.0.1, port: 8722, session_hours: 8}
```

The `grouping.tags` line is an example; the default is no tags (`tags: []`).

In the Docker image use `database: /data/sshbite.db` and paths under `/etc/sshbite/`.

## Keys

### Top level

| Key | Default | Meaning |
|---|---|---|
| `database` | `/var/lib/sshbite/sshbite.db` | The SQLite database. Created on first use with mode 0600 (directory 0700). Scanner and UI share it. |

### `entry`

| Key | Default | Meaning |
|---|---|---|
| `entry.host` | – (required) | Name or address of the entry host (jump host) as reached from the SSHBITE machine. Always scanned, at depth 0. |
| `entry.port` | `22` | Its SSH port. |
| `entry.host_keys` | `[]` | Pinned host keys, each `"<algorithm> <base64> [comment]"` as printed by `ssh-keyscan`. Any match verifies the entry. Empty = every scan aborts (exit 3) and `config validate` fails. See [install.md](install.md#pin-the-entry-host-key). |

### `audit`

| Key | Default | Meaning |
|---|---|---|
| `audit.user` | `sshbite` | Account used on every host and every hop. |
| `audit.key_file` | `/etc/sshbite/audit_ed25519` | The audit private key. Must be a regular file with mode 0600, readable by the user running SSHBITE. It is the only key SSHBITE ever uses; agents and keys found on targets are never used. |
| `audit.key_passphrase_env` | `null` | Name of an environment variable holding the key's passphrase (not the passphrase itself). Unset variable = config error. |

### `privilege`

| Key | Default | Meaning |
|---|---|---|
| `privilege.mode` | `sudo` | `sudo`: probe `sudo -n /bin/true`, then run the collector as `sudo -n /bin/sh -s`. `sudo-login`: the same with `-i` (root's login environment). `none`: never call sudo; every host is scanned unprivileged and marked `partial`. With a sudo password (`--ask-sudo-password` or `SSHBITE_SUDO_PASSWORD`) a host that asks for one is tried with `sudo -S -k -p ''`. |

### `crawl`

| Key | Default | Meaning |
|---|---|---|
| `crawl.max_depth` | `10` | Hosts more than this many steps from depth 0 are listed as `max_depth`, not scanned. `0` = entry and seeds only. Range 0–100. CLI: `--max-depth`. |
| `crawl.max_hosts` | `1000` | Most hosts queued in one scan; further references are listed as `max_hosts`. CLI: `--max-hosts`. |
| `crawl.include` | `[]` | CIDRs (`10.1.0.0/16`) or host name globs (`*.corp.example`). If set, a discovered host is scanned only if one of its names (glob, case-insensitive) or IPs (CIDR) matches; others are `out_of_scope`. Empty = no restriction. The entry host is always scanned. |
| `crawl.exclude` | `[]` | Same syntax. A matching host is never connected to, only listed as `excluded`. Exclude wins over include and over seeds. |
| `crawl.chain_fallback` | `true` | If the default route (entry → target) fails with a network error, retry along the path the host was discovered on (entry → parent → … → target), with the audit account and a host-key check on every hop. Authentication failures do not trigger it. |
| `crawl.hash_probe_include_cidrs` | `true` | Hashed known_hosts lines (`\|1\|…`) are matched against every name and IP known in the scan; with this on, also against every IPv4 address in the `include` CIDRs. No connection is made for this. |
| `crawl.hash_probe_max_addresses` | `4096` | Upper limit of include-CIDR addresses tried for hashed lines. |
| `crawl.ssh_port` | `22` | Port used for references and seeds that name no port. |

### `seeds`

All seeds start at depth 0 next to the entry host. They are optional: the normal case is the crawl from the
entry host alone.

| Key | Default | Meaning |
|---|---|---|
| `seeds.hosts_file` | `null` | A text file: one `host`, `host:port` or `[host]:port` per line; `#` starts a comment. |
| `seeds.cidrs` | `[]` | Networks whose every address is TCP-probed **from the entry host** (2 s) before scanning; silent addresses get status `no_ssh` and are hidden by default. At most 65,536 addresses in total. |
| `seeds.ansible_inventories` | `[]` | Static Ansible inventories, INI or YAML (`.yml`/`.yaml` or starting with `all:`/`---`). `ansible_host`, `ansible_port` and ranges like `web[01:10]` are used; the first group becomes the host's `ansible` group in the heatmap. Dynamic inventories (scripts, plugins) are not run. |

### `hostkeys`

| Key | Default | Meaning |
|---|---|---|
| `hostkeys.mode` | `tofu` | `tofu`: the first key seen for an address, port and algorithm is stored; a different key later gives status `hostkey_mismatch` and the critical finding `host_key_changed`, and the host is not logged in to until `sshbite hostkey accept ADDR[:PORT]`. `strict`: a host's key must be in `known_hosts_file` under one of its names or addresses, else status `hostkey_unknown`. Hops are checked the same way. The entry host is always checked against `entry.host_keys`. |
| `hostkeys.known_hosts_file` | `null` | OpenSSH known_hosts file for `strict` (required then). |

### `limits`

| Key | Default | Meaning |
|---|---|---|
| `limits.concurrency` | `20` | Hosts collected at the same time. CLI: `--concurrency`. |
| `limits.host_timeout` | `30` | Seconds for one host in total: connect, authenticate, sudo probe and collect. Exceeded = status `timeout`. CLI: `--timeout`. |
| `limits.connect_timeout` | `10` | Seconds per hop to connect. |
| `limits.entry_connections` | `4` | SSH connections to the entry host; all tunnels are multiplexed over them. |
| `limits.max_output_mb` | `32` | Most collector output read from one host. Reaching it gives status `output_limit`; the data read so far is kept and the host counts as partial. |

### `rules`

| Key | Default | Meaning |
|---|---|---|
| `rules.strength.good` / `.ok` / `.weak` / `.critical` | see example | Key strength classes. Each item is an algorithm name (`ssh-ed25519`) or `algorithm` + `>=`, `<=`, `>`, `<` or `==` + bits (`"ssh-rsa>=3072"`; quote it in YAML). The classes are tried in the order good, ok, weak, critical, and the first matching item wins; a key matching nothing is `unknown`. `critical` keys get the finding `key_strength_critical`, `weak` keys `key_strength_weak`. |
| `rules.many_hosts_threshold` | `10` | A key authorized on at least this many hosts gets the finding `key_on_many_hosts`. Minimum 2. |
| `rules.ignore_audit_key` | `true` | Leave the audit key's own authorized_keys lines out of edges and findings. |

### `grouping`

| Key | Default | Meaning |
|---|---|---|
| `grouping.tags` | `[]` | List of `{name, match}`. `match` uses the include/exclude syntax. A host gets the first tag that matches, else `untagged`. The heatmap can group by tag. |

### `web`

| Key | Default | Meaning |
|---|---|---|
| `web.bind` | `127.0.0.1` | Address `sshbite serve` listens on. A non-loopback address needs `--tls-cert` and `--tls-key`. Ignored inside the Docker image (`SSHBITE_IN_CONTAINER=1`), which listens on `0.0.0.0`; publish the port on `127.0.0.1` only. CLI: `--bind`. |
| `web.port` | `8722` | Port. CLI: `--port`. |
| `web.session_hours` | `8` | Lifetime of a UI login session in hours. |

## Environment variables

| Variable | Meaning |
|---|---|
| `SSHBITE_CONFIG` | Config path when `-c` is not given. |
| `SSHBITE_SUDO_PASSWORD` | sudo password for `scan`, as an alternative to `--ask-sudo-password` (e.g. for a timer). Removed from the environment right after it is read; never stored or logged. |
| `SSHBITE_IN_CONTAINER` | `1` in the Docker image: `serve` binds `0.0.0.0` without TLS. Do not set it elsewhere. |
| the one named in `audit.key_passphrase_env` | Passphrase of the audit key. |
