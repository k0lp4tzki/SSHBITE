# Install and set up

SSHBITE runs on one machine (the "SSHBITE machine") that can reach the **entry host** – a jump host
whose host key you have verified. Everything else is reached through that entry host. You need:

- the SSHBITE machine: Python 3.12 with pip, **or** Docker;
- an audit account `sshbite` with one audit key on every Linux/OpenSSH host you want to audit;
- root for the read-only collector through sudo – recommended as the installed collector, which does
  not make the audit key root-equivalent (optional, but without it a host is only scanned partially).

Contents: [pip](#install-with-pip) · [Docker](#install-with-docker) ·
[audit key and account](#the-audit-key-and-account) ·
[privileges: installed collector](#privileges-installed-collector-recommended) ·
[legacy sudoers](#legacy-sudo-binsh--s-equivalent-to-full-root) ·
[pin the entry host key](#pin-the-entry-host-key) · [first scan](#first-scan-and-first-login)

## Install with pip

SSHBITE needs Python 3.12 or later. Install from a checkout of this repository; the build runs
`npm ci && npm run build` in `frontend/`, so Node 22 is needed **only to build** (or install a wheel
someone built for you – it contains the frontend).

```sh
python3.12 -m venv /opt/sshbite
/opt/sshbite/bin/pip install --require-hashes -r requirements-runtime.lock   # pinned, with hashes
/opt/sshbite/bin/pip install --no-deps .                              # SSHBITE itself (builds the frontend)
ln -s /opt/sshbite/bin/sshbite /usr/local/bin/sshbite
sshbite --version
```

Build a wheel once and install it elsewhere without Node:

```sh
pip wheel --no-deps -w dist .          # dist/sshbite-0.1.0-py3-none-any.whl
pip install --no-deps dist/sshbite-0.1.0-py3-none-any.whl    # after requirements-runtime.lock, as above
```

Create a system account to run SSHBITE and its directories:

```sh
useradd --system --home-dir /var/lib/sshbite --shell /usr/sbin/nologin sshbite-app
install -d -m 0700 -o sshbite-app -g sshbite-app /var/lib/sshbite      # database
install -d -m 0700 -o sshbite-app -g sshbite-app /etc/sshbite          # config + audit key
```

Run every `sshbite` command as that account (`sudo -u sshbite-app sshbite …`), so the database stays
owned by it. SSHBITE creates the database with mode 0600 and its directory with 0700.

## Install with Docker

The `Dockerfile` builds in three stages: `node:22` builds the frontend, a Python stage builds the
wheel, and the `python:3.12-slim` runtime installs `requirements-runtime.lock` (runtime dependencies
only – no test tools) with `--require-hashes` plus the wheel. The image:

- runs as uid/gid **10001** (`sshbite`), never as root;
- sets `SSHBITE_IN_CONTAINER=1`, so `sshbite serve` without `--bind` listens on `0.0.0.0:8722` inside
  the container (publish it on `127.0.0.1` only – the UI has no TLS in the container). For access from
  other machines put a TLS reverse proxy in front ([operations.md](operations.md#behind-a-reverse-proxy-tls-at-the-proxy));
  an explicit non-loopback `--bind` without TLS is refused unless `web.secure_cookie` is set;
- reads its config from `/etc/sshbite/sshbite.yaml` (`SSHBITE_CONFIG`) and keeps its data in `/data`;
- declares the volumes `/data` and `/etc/sshbite` – mount `/etc/sshbite` **read-only**;
- starts `sshbite serve` by default.

```sh
docker build -t sshbite:0.1.0 .
```

Prepare `/etc/sshbite` on the Docker host (key and config are created in the next sections). The
container user must be able to read both files, and the key must be mode 0600:

```sh
install -d -m 0700 /etc/sshbite
# ... create /etc/sshbite/audit_ed25519 and /etc/sshbite/sshbite.yaml (below) ...
chown -R 10001:10001 /etc/sshbite
chmod 0600 /etc/sshbite/audit_ed25519 /etc/sshbite/sshbite.yaml
```

In the config, the paths are paths **inside the container**:

```yaml
database: /data/sshbite.db
audit:
  key_file: /etc/sshbite/audit_ed25519
```

Start it with [`compose.example.yaml`](compose.example.yaml) (copy it next to your other compose
files and adjust `build:`/`image:`):

```sh
docker compose -f docs/compose.example.yaml up -d
docker exec -it sshbite sshbite config validate --connect
docker exec -it sshbite sshbite user add admin
docker exec -it sshbite sshbite scan --ask-sudo-password
# open http://127.0.0.1:8722/
```

Or without compose:

```sh
docker run -d --name sshbite --restart unless-stopped \
  -v sshbite-data:/data -v /etc/sshbite:/etc/sshbite:ro \
  -p 127.0.0.1:8722:8722 --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true sshbite:0.1.0
```

`docker exec` runs commands in the running container, as uid 10001, with the same config and database.
Use `docker exec -it` for every command that asks for a password (`user add`, `user passwd`,
`scan --ask-sudo-password`): without a terminal SSHBITE refuses to read a password, because it could be
echoed. The image has no ssh client tools: create keys and run `ssh-keyscan` on the Docker host.

**Try it on the test lab first:** `docker compose -f compose.lab.yaml up -d --build` at the top of this
repository starts the 13 lab hosts and the SSHBITE image, which validates the entry, creates the UI user
`admin`, runs one scan and serves the UI on http://127.0.0.1:8722/ (`lab/demo/start.sh`). The admin
password is `SSHBITE_DEMO_PASSWORD` if you set it (e.g. in `.env`); otherwise a random one is printed once:
`docker compose -f compose.lab.yaml logs sshbite | grep 'LAB DEMO LOGIN'`. The lab, its config and its
keys (`lab/keys/`, including private host keys and the audit key) are **test material – never use them
for real systems**.

## The audit key and account

SSHBITE logs in to every host as one account (default `sshbite`, config `audit.user`) with one key
(`audit.key_file`). Use a dedicated ed25519 key that is used for nothing else.

1. Create the key on the SSHBITE machine (for Docker: on the Docker host):

   ```sh
   ssh-keygen -t ed25519 -N '' -C "sshbite-audit $(date +%F)" -f /etc/sshbite/audit_ed25519
   chmod 600 /etc/sshbite/audit_ed25519
   ```

   SSHBITE refuses a key file that is not mode 0600. With a passphrase, set
   `audit.key_passphrase_env` to the name of an environment variable that holds it.

2. Deploy the account and the public key on every target, including the entry host. **With
   `privilege.mode: installed` (recommended) follow
   [Privileges: installed collector](#privileges-installed-collector-recommended) instead**: there the
   account keeps the shell `/bin/sh`, its home and `~/.ssh` belong to root (the account cannot change its
   own keys), and the key line runs the gate. For the legacy modes, with your usual configuration
   management or by hand:

   ```sh
   useradd --create-home --shell /bin/sh sshbite
   install -d -m 0700 -o sshbite -g sshbite ~sshbite/.ssh
   printf 'restrict %s\n' "$(cat audit_ed25519.pub)" > ~sshbite/.ssh/authorized_keys
   chown sshbite:sshbite ~sshbite/.ssh/authorized_keys; chmod 600 ~sshbite/.ssh/authorized_keys
   ```

   The account needs a POSIX shell (`/bin/sh`): SSHBITE sends its collector script on stdin to
   `/bin/sh -s`. `restrict` is fine on every host: it disables pty, agent, X11 and port forwarding.
   **On the entry host and on hosts used as hops** SSHBITE opens `direct-tcpip` channels to the next
   host, so there use `restrict,port-forwarding` (or no options) instead of `restrict`, and sshd
   must allow `AllowTcpForwarding yes` (or `local`) for this account.

   Restricting the key with `from="<entry host IP>,<SSHBITE machine IP>"` is a good idea; with the
   chained fallback (`crawl.chain_fallback`) a host may also be reached via its discovering host – list
   those hops too, or set `chain_fallback: false`.

3. If an `AllowUsers`/`AllowGroups` line exists in `sshd_config`, add `sshbite` to it.

SSHBITE ignores the audit key in its own results (`rules.ignore_audit_key: true`), so its own
`authorized_keys` lines do not show up as edges or findings.

## Privileges: installed collector (recommended)

### Why

Without root, the collector cannot read other users' `~/.ssh` and `/etc/shadow`. The legacy way to give
it root – a sudoers rule for `/bin/sh -s` – is **equivalent to full root** for whoever holds the audit
key, because the shell runs whatever arrives on stdin. With `privilege.mode: installed` that is no longer
so:

- The collector is installed on every host as a root-owned file, `sshbite-collect`. The only sudo rule
  for the account allows exactly this file, without arguments.
- The audit key may only run a fixed gate, `sshbite-gate` (`command=` in `authorized_keys`). The gate
  compares the requested command literally with three strings and refuses everything else.
- SSHBITE sends no script to a shell, never sends a sudo password and does not fall back to an
  unprivileged scan.

Whoever holds the audit key (and connects from an allowed address) can then only run the probe, start the
installed read-only collector as root, resolve names and – on the entry host – forward to SSH ports. They
cannot open a shell, run a command of their own, hand a script to a shell, read root files outside the
inventory or write anything. What remains: the key reveals the inventory (see
[review.md](review.md#residual-risk-the-audit-key-reveals-the-inventory)).

The three commands SSHBITE sends in this mode (P = `privilege.collector_path`, all on their own exec
channel, `sshbite collector show` prints them):

| Step | Command | stdin |
|---|---|---|
| Probe | `sudo -n -l P` | empty |
| Collector | `sudo -n P` | empty |
| Name resolution | `<dir of P>/sshbite-resolve` | the names, one per line (data only) |

### Export and checksums

On the SSHBITE machine, write the files into a new, empty directory:

```sh
sshbite collector export ./sshbite-export          # --collector-path P for another location
cd sshbite-export && sha256sum -c SHA256SUMS        # every line must say OK
```

With Docker:

```sh
docker run --rm --user "$(id -u)" -v "$PWD/sshbite-export:/out" sshbite:<version> sshbite collector export /out
```

| File | What it is |
|---|---|
| `sshbite-collect` | the collector: `#!/bin/sh` and `collect.sh` byte for byte (the same text `sshbite collector show` prints) |
| `sshbite-resolve` | the name resolution: `#!/bin/sh` and `resolve.sh` |
| `sshbite-gate` | the forced command; read it – it is about 50 lines |
| `sudoers.d-sshbite` | the one sudo rule |
| `authorized_keys.sshbite` | the three key-line variants (A, B, C below) |
| `SHA256SUMS` | the SHA-256 of the five files |

The default for P is `privilege.collector_path` from the config if it can be loaded, else
`/usr/local/libexec/sshbite/sshbite-collect`. Resolve and gate always sit next to the collector. Read the
files before you install them. Distributing them with your own configuration management is the intended
way; the commands below show what it has to do.

### Install on every host (as root)

```sh
id sshbite || useradd -m -s /bin/sh sshbite; passwd -l sshbite     # no sudo/wheel group
usermod -s /bin/sh sshbite                  # also for an account that existed before: shell /bin/sh
install -d -m 0755 -o root -g root /usr/local/libexec/sshbite
install -m 0755 -o root -g root sshbite-collect sshbite-resolve sshbite-gate /usr/local/libexec/sshbite/
install -m 0440 -o root -g root sudoers.d-sshbite /etc/sudoers.d/sshbite && visudo -cf /etc/sudoers.d/sshbite
chown root:root /home/sshbite && chmod 0755 /home/sshbite
install -d -m 0755 -o root -g root /home/sshbite/.ssh
install -m 0644 -o root -g root authorized_keys.sshbite.edited /home/sshbite/.ssh/authorized_keys
sudo -l -U sshbite        # must list only: (root) NOPASSWD: /usr/local/libexec/sshbite/sshbite-collect ""
stat -c '%U %a %n' /usr /usr/local /usr/local/libexec /usr/local/libexec/sshbite/*   # all root, none group/other-writable
```

- `visudo -cf` must say `parsed OK`.
- **Remove every other sudoers rule for `sshbite`**, for example `NOPASSWD: ALL` or `/bin/sh -s` from the
  legacy setup – otherwise the key stays root-equivalent. `sudo -l -U sshbite` shows what is left.
- The rule is only safe if the collector file and every directory up to it are owned by root and not
  writable by group or others. The `stat` line checks that.
- `authorized_keys.sshbite.edited` is your copy of `authorized_keys.sshbite` with the variant for this
  host (next section). Home and `.ssh` belong to root, so the account cannot change its own keys.
- If the account `sshbite` existed before, work through the next section as well: `useradd` leaves an
  existing account as it is.

### An account sshbite that existed before

After an incident an old `sshbite` account is exactly where a leftover key or group would hide. The
install above makes home and `.ssh` root's and replaces `authorized_keys`, but it leaves every other file,
the groups and the login shell as they were. Check each point and remove what is left (as root):

```sh
getent passwd sshbite | cut -d: -f7       # must print /bin/sh (usermod -s /bin/sh sshbite above)
id sshbite                                # only its own group - no sudo, wheel, admin, adm, docker, lxd, ...
gpasswd -d sshbite wheel                  # for every other group id shows (here: wheel)
ls -la ~sshbite ~sshbite/.ssh             # what is there
ls -A ~sshbite/.ssh                       # must print exactly: authorized_keys
rm -i ~sshbite/.ssh/authorized_keys2      # and every other file in .ssh (old keys, rc, environment, config)
crontab -l -u sshbite; ps -u sshbite      # no cron jobs, no running processes of the account
sshd -T | grep -Ei 'authorizedkeysfile|acceptenv|permituserenvironment'
```

- **`authorized_keys2` and other files in `.ssh`**: sshd reads `.ssh/authorized_keys2` by default (Debian:
  `AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2`). A key line there has no `command=` and
  no `from=` – it logs in to a normal shell as `sshbite`, and that account may run the collector as root.
  `.ssh` may hold only `authorized_keys`.
- **Groups**: a group like `sudo` or `wheel` brings back sudo rules for all its members; `sudo -l -U
  sshbite` must still list only the collector. Other groups (`docker`, `lxd`, `disk`, `adm`) give root or
  root-readable data without sudo.
- **Other files in the home** (`.profile`, `.bashrc`, …): they do not run – the forced command runs through
  `/bin/sh -c`, which reads no start-up file, and `restrict` stops `~/.ssh/rc`. Remove them if you want a
  clean home; they cannot be changed by the account any more (home is root's).
- **`sshd -T`**, the expected output:

  ```
  authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
  acceptenv LANG
  acceptenv LC_*
  permituserenvironment no
  ```

  `authorizedkeysfile` lists the files sshd reads for every account – each of them must be absent in
  `~sshbite` except `authorized_keys` (or the path you use instead). `acceptenv` may list only locale
  variables (`LANG`, `LC_*`, on RHEL also `LANGUAGE` and `XMODIFIERS`), or nothing; never `*`, `PATH`,
  `LD_*` or `BASH_ENV`. `permituserenvironment` must be `no`, otherwise `~/.ssh/environment` would be read.

### The authorized_keys variants

One line per host, from `authorized_keys.sshbite`; replace `<AUDIT-PUBLIC-KEY>` with the content of
`/etc/sshbite/audit_ed25519.pub` and the address placeholders:

```
# (A) entry host: login only from the scanner, forwarding only to SSH ports (add permitopen="*:<PORT>" per extra SSH port)
#     permitlisten="localhost:22": no remote listener (ssh -R). authorized_keys knows no "none" here (sshd then
#     rejects the whole line); localhost:22 is sshd's own port, so the only listener it allows can never be opened.
restrict,port-forwarding,permitopen="*:22",permitlisten="localhost:22",from="<SCANNER-IP>",command="/usr/local/libexec/sshbite/sshbite-gate" <AUDIT-PUBLIC-KEY>
# (B) every other host: login only from the entry host, no forwarding
restrict,from="<ENTRY-HOST-IP>",command="/usr/local/libexec/sshbite/sshbite-gate" <AUDIT-PUBLIC-KEY>
# (C) only for crawl.chain_fallback: intermediate hops, from = previous hop; no remote listener as in (A)
restrict,port-forwarding,permitopen="*:22",permitlisten="localhost:22",from="<PREVIOUS-HOP-IP>",command="/usr/local/libexec/sshbite/sshbite-gate" <AUDIT-PUBLIC-KEY>
```

- **A** is for the entry host. `<SCANNER-IP>` is the address the entry host sees for the SSHBITE machine
  (with Docker port publishing that can be a gateway address; a CIDR is allowed).
- **B** is for every other host. `<ENTRY-HOST-IP>` is the entry host's address *in that host's network*.
- **C** is for hosts SSHBITE uses as a hop to reach hosts the entry host cannot reach
  (`crawl.chain_fallback`); a host reached through such a hop needs `from=` with the hop's address. If a
  scan shows a host as `auth_failed` with a route over a hop, the `from=` of that host is the place to look.
- If `sshd_config` has `AllowUsers`/`AllowGroups`, add `sshbite`. The entry host (and C hosts) need
  `AllowTcpForwarding yes` (or `local`) for this account.
- **Remote forwarding (`ssh -R`)**: A and C allow forwarding only *to* SSH ports (`-L`, that is how SSHBITE
  crawls). `permitlisten="localhost:22"` refuses every TCP listener the key holder asks for (checked on
  Debian 12 / OpenSSH 9.2 and AlmaLinux 9 / OpenSSH 9.9). OpenSSH has no `authorized_keys` option for
  listeners on a Unix socket (`ssh -R /tmp/x.sock:…`): with `port-forwarding` such a socket can be created
  where `sshbite` may write (mode 0600 with the default `StreamLocalBindMask`, so only `sshbite` and root can
  connect). To close that too, add to `sshd_config` on A and C hosts (checked in the lab on both systems:
  Unix and TCP listeners refused, `-L` to port 22 and the collector work):

  ```
  Match User sshbite
      AllowTcpForwarding local
      AllowStreamLocalForwarding no
  ```

### Config

```yaml
privilege:
  mode: installed
  collector_path: /usr/local/libexec/sshbite/sshbite-collect    # only needed for another location
```

`privilege.password_scope` must be empty in this mode, `scan --ask-sudo-password` is refused, and a set
`SSHBITE_SUDO_PASSWORD` only gives a warning. Details: [configuration.md](configuration.md#privilege).

### Check

```sh
sshbite config validate --connect
```

The last line must read:

```
entry OK, pinned key matches, sudo: root (installed /usr/local/libexec/sshbite/sshbite-collect, collector B=<12 hex> matches)
```

`--connect` runs the probe and the collector on the entry host and reads only the collector's first line;
that leaves one more sudo log entry there. On a failure the line reads `sudo: FAILED - <message>` and the
command exits with 3, because a scan would fail on the entry host the same way. The messages are listed
below.

### After an SSHBITE update

When an update changes the collector, every host reports
`installed collector version differs from this SSHBITE …` and is shown as `collector_error`. Export again,
check the checksums, install only the new `sshbite-collect` on every host and scan again. Gate, sudoers
and `authorized_keys` stay the same as long as the path stays the same (compare with `sha256sum -c`).

### Switching from mode sudo (or from a hand-made gate)

1. Install the files on all hosts (new gate, new sudoers file, new `authorized_keys`; remove the old
   sudoers rules).
2. Then set `privilege.mode: installed` in the config.

Do not scan between the two steps: the new gate refuses the commands of the old modes with exit 126, so a
scan in mode `sudo` against an installed host ends in `no collector output: sshbite-gate: denied …`.

### Error messages

In mode installed a host never falls back to `partial`/`unprivileged`. If something is wrong it is
`collector_error` in the UI and in `sshbite scans show`, with one of these messages (P = the collector
path, `<l>` = the first line of stderr):

| Message | Meaning and fix |
|---|---|
| `privilege.mode installed: refused by sshbite-gate on this host: <l>` | The gate refused the command: `privilege.collector_path` differs from the path the gate was exported for, or an old gate is installed. Export with the right path and install the new gate. |
| `privilege.mode installed: sudo asks for a password - the sudoers rule for P must be NOPASSWD` | sudo wants a password. Either the rule lacks `NOPASSWD:` or `/etc/sudoers.d/sshbite` is missing altogether – sudo answers both the same way. Install `sudoers.d-sshbite` and check with `sudo -l -U sshbite`. |
| `privilege.mode installed: collector not installed at P` | The sudo rule exists, the file does not. Install `sshbite-collect` at P. |
| `privilege.mode installed: sudo does not allow P for this account (sudo -n -l exit <rc>: <l>)` | sudo has rules for `sshbite`, but none for P (`<l>` is then often empty). Install `sudoers.d-sshbite` and remove the other rules. |
| `privilege.mode installed: installed collector version differs from this SSHBITE (expected B=<x>, host has B=<y>) - run 'sshbite collector export' and reinstall sshbite-collect` | The host has the collector of another SSHBITE version. See "After an SSHBITE update". |
| `no collector output: <l>` | The collector printed nothing usable; `<l>` says why. |

### Prerequisite: util-linux

The collector is a POSIX `sh` script and needs the usual base tools (`stat`, `head`, `awk`, `getent`,
`ssh-keygen`, `sshd`). It reads files in user homes (`~/.ssh`, every `AuthorizedKeysFile` path) as their
owner, with `setpriv` from util-linux (`/usr/bin/setpriv`, on Debian ≥ 10 and RHEL/EL ≥ 8 part of the base
system) – so a user who swaps a file for a symlink gets nothing into the scan that they could not read
themselves ([review.md](review.md#files-in-user-homes-are-read-as-their-owner)). Make sure `util-linux` is
installed on every host. This applies to every `privilege.mode`.

Without `setpriv` the collector does **not** fall back to reading as root: it reads nothing in user homes,
and the host is shown as `partial` with the reason `setpriv (util-linux) missing: files in user homes not
read`. Host keys, sshd settings and the shadow summary are still collected. Install util-linux and scan
again.

A file in a home that its owner cannot read – for example a root-owned 0600 `authorized_keys2` – is shown
on the host as `unreadable by account: PATH`; the host stays `ok`. sshd reads authorized_keys as the user
too, so keys in such a file do not work; fix the owner or remove the file.

### Not tested

The lab tests this mode on Debian 12 (OpenSSH 9.2, sudo 1.9.13, util-linux 2.38) and on AlmaLinux 9.9
(RHEL-compatible; OpenSSH 9.9, sudo 1.9.17, util-linux 2.37). Not tested: SELinux in enforcing mode (the
lab's containers do not enforce it), OpenSSH older than 8.7 and Busybox-based systems.

### Further hardening (not implemented)

Further hardening (not implemented): run the collector with only CAP_DAC_READ_SEARCH instead of root.

## Legacy: sudo /bin/sh -s (equivalent to full root)

**Warning: this setup is equivalent to full root for whoever holds the audit key.** Use it only where you
cannot install files on the hosts; prefer [the installed collector](#privileges-installed-collector-recommended).

Without root, the collector cannot read other users' `~/.ssh` and `/etc/shadow`; the host is then
`partial`. The commands SSHBITE runs with sudo are fixed (see `sshbite collector show`). sudo is always
called by its absolute path – `/usr/bin/sudo`, or `/bin/sudo` only where `/usr/bin/sudo` does not exist
(decided by a fixed `test -x` on the host, never by the audit account's `PATH`); the table shortens that
to `sudo`:

| `privilege.mode` | Probe | Collector |
|---|---|---|
| `sudo` (default) | `sudo -n /bin/true` | `sudo -n /bin/sh -s` |
| `sudo-login` | `sudo -n -i /bin/true` | `sudo -n -i /bin/sh -s` |
| (with a sudo password) | `sudo -S -k -p '' /bin/true` | `sudo -S -k -p '' /bin/sh -s` |
| `none` | – | `/bin/sh -s` (unprivileged) |

Put this in `/etc/sudoers.d/sshbite` (mode 0440, check with `visudo -cf /etc/sudoers.d/sshbite`):

```
# SSHBITE audit account: root for the read-only collector, no password, no lecture
Defaults:sshbite !lecture
sshbite ALL=(root) NOPASSWD: /bin/true, /bin/sh -s
```

This line is for `privilege.mode: sudo`. With `sudo-login`, sudo runs root's login shell with the command
as `-c` argument, which a command list cannot express cleanly – use `NOPASSWD: ALL` there.

Be clear about what this grants: `/bin/sh -s` runs whatever arrives on stdin as root, so the line is
**equivalent to full root** for whoever holds the audit key. Restricting it to these two commands only
documents the intent and keeps other commands out of the sudo log. Protect the audit key accordingly
(mode 0600, a dedicated machine, `from=` restriction). What SSHBITE sends is fixed and reviewable:
[review.md](review.md).

If your policy demands a sudo password, drop `NOPASSWD:` and scan with `--ask-sudo-password`
([scanning.md](scanning.md#sudo-passwords)). Be aware that with Debian's default sudoers every scan then
makes sudo send a *"SECURITY information"* mail per host, because the first, non-interactive probe is
refused ([side-effects.md](side-effects.md#sudo-the-incident-mail-on-refused-sudo)). Where `sshbite` has
no sudo rule at all, the host is scanned unprivileged and marked `partial`. Give the audit account a
password of its own that is used nowhere else and rotate it after the scan: a compromised host can imitate
a sudo prompt and capture it ([operations.md](operations.md#the-sudo-password)).

## Pin the entry host key

SSHBITE refuses to scan unless the entry host presents a key listed in `entry.host_keys`. Get the key
over the network and compare its fingerprint with the one read **on the entry host's console**
(not over the same network path):

```sh
# on the SSHBITE machine
ssh-keyscan -t ed25519 -p 22 jump01.corp.example 2>/dev/null | tee /tmp/entry.keys
ssh-keygen -lf /tmp/entry.keys
# on the entry host's console (or via your out-of-band management)
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

When the fingerprints match, put the key into the config without the host name, as
`"<algorithm> <base64>"`:

```yaml
entry:
  host: jump01.corp.example
  port: 22
  host_keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."]
```

Any listed key matches, so you can pin the ed25519 and the ecdsa key at once, or the old and the new key
during a host key rotation. On a mismatch the scan aborts with exit code 3:

```
error: ENTRY HOST KEY MISMATCH – scan aborted
  offered: ssh-ed25519 SHA256:…
  pinned:  ssh-ed25519 AAAA…
```

Host keys of all other hosts are trusted on first use (or checked against a known_hosts file, see
`hostkeys` in [configuration.md](configuration.md#hostkeys)).

## First scan and first login

```sh
sshbite init-config > /etc/sshbite/sshbite.yaml     # then edit entry.*, audit.*, database
chmod 600 /etc/sshbite/sshbite.yaml
sshbite config validate --connect
```

`config validate` checks the schema, the file modes and the seeds; `--connect` also connects to the entry
host and probes sudo there. It ends with a line like

```
entry OK, pinned key matches, sudo: root
```

Then create a UI login (password prompted twice, at least 12 characters), run the first scan and start
the UI:

```sh
sshbite user add admin
sshbite scan
sshbite serve            # http://127.0.0.1:8722/
```

The UI listens on loopback only. To reach it from another machine, use an SSH tunnel
(`ssh -L 8722:127.0.0.1:8722 sshbite-machine`) or give `serve` a certificate: a non-loopback `--bind`
requires `--tls-cert` and `--tls-key`.

Next: [scanning.md](scanning.md) and [operations.md](operations.md).
