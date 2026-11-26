# Install and set up

SSHBITE runs on one machine (the "SSHBITE machine") that can reach the **entry host** – a jump host
whose host key you have verified. Everything else is reached through that entry host. You need:

- the SSHBITE machine: Python 3.12 with pip, **or** Docker;
- an audit account `sshbite` with one audit key on every Linux/OpenSSH host you want to audit;
- sudo for that account (optional, but without it a host is only scanned partially).

Contents: [pip](#install-with-pip) · [Docker](#install-with-docker) ·
[audit key and account](#the-audit-key-and-account) · [sudoers](#sudoers) ·
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

2. Deploy the account and the public key on every target, including the entry host. With your usual
   configuration management, or by hand:

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

## Sudoers

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
