# Operations: services, nightly scans, backup, update

Contents: [the UI as a service](#the-ui-as-a-systemd-service) ·
[behind a reverse proxy](#behind-a-reverse-proxy-tls-at-the-proxy) · [nightly scan](#nightly-scan-with-a-systemd-timer) ·
[the sudo password](#the-sudo-password) · [Docker](#docker) · [UI logins](#ui-logins) · [backup](#backup-and-restore) ·
[update](#update) · [retention](#retention)

## The UI as a systemd service

[`systemd/sshbite-serve.service`](systemd/sshbite-serve.service) runs `sshbite serve` as the account
`sshbite-app` from [install.md](install.md#install-with-pip), with the database in `/var/lib/sshbite`:

```sh
cp docs/systemd/sshbite-serve.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sshbite-serve.service
journalctl -u sshbite-serve.service        # "SSHBITE UI on http://127.0.0.1:8722/ ..."
```

`serve` listens on `web.bind`:`web.port` (127.0.0.1:8722). It refuses a non-loopback address unless
started with `--tls-cert FILE --tls-key FILE`, or TLS ends at a reverse proxy and `web.secure_cookie: true`
is set (next section). `--insecure-bind` overrides the refusal and logs a warning – the login password and
the session cookie then cross the network in clear text; do not use it outside a test. The unit is
hardened (`ProtectSystem=strict`, only `/var/lib/sshbite` writable); adjust `ReadWritePaths` if your
database lives elsewhere.

In the Docker image (`SSHBITE_IN_CONTAINER=1`) `serve` without `--bind` listens on 0.0.0.0 inside the
container, because the compose file publishes the port on `127.0.0.1` of the host only. An explicit
`--bind` to a non-loopback address gets no such exception: the same rule as above applies.

## Behind a reverse proxy (TLS at the proxy)

For access from other machines, put a reverse proxy with TLS in front of SSHBITE and keep SSHBITE itself
on loopback (or on a private container network). Two settings make SSHBITE fit that setup:

```yaml
web:
  bind: 127.0.0.1           # the proxy connects here; in Docker: publish 127.0.0.1:8722:8722
  port: 8722
  secure_cookie: true       # the session cookie gets "Secure": browsers send it over HTTPS only
  trusted_proxies: [127.0.0.1]   # the proxy's address as SSHBITE sees it (IPs or CIDRs)
```

- **`secure_cookie`** – the cookie carries `Secure`, so the browser never sends it over plain HTTP. With
  `--tls-cert` it is always on. With `secure_cookie` and no proxy, a browser on plain `http://` cannot
  log in (except on `localhost`) – that is intended.
- **`trusted_proxies`** – only when the TCP peer is in this list does SSHBITE take the client address for
  the per-IP login limit (20 failures in 15 minutes → HTTP 429) from `X-Forwarded-For`, and then only its
  **last** entry: the address the proxy itself saw. Earlier entries are supplied by the client and are
  ignored. From any other peer the header is ignored. Without this setting every user behind the proxy
  shares one address, and 20 failed logins of anyone lock everyone out for 15 minutes.
- In Docker the proxy usually reaches SSHBITE over a container network: list that proxy container's
  address (or the network's CIDR, if nothing else on it is untrusted) in `trusted_proxies`, start the
  container with `sshbite serve --bind 0.0.0.0` and keep `secure_cookie: true` – without it SSHBITE refuses
  that bind.

Example for nginx on the same host (certificate paths are yours):

```nginx
server {
    listen 443 ssl;
    server_name sshbite.corp.example;
    ssl_certificate     /etc/ssl/sshbite/fullchain.pem;
    ssl_certificate_key /etc/ssl/sshbite/privkey.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;
    client_max_body_size 64k;                    # SSHBITE answers larger /api bodies with 413 anyway

    location / {
        proxy_pass http://127.0.0.1:8722;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;   # one hop: exactly the client's address
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

`proxy_set_header X-Forwarded-For $remote_addr` replaces whatever the client sent; with
`$proxy_add_x_forwarded_for` the client's own value is kept in front, which SSHBITE ignores because it
reads only the last entry. Check it: log in at `https://sshbite.corp.example/`, the browser's developer
tools show the cookie `sshbite_session` with *Secure*; 20 wrong passwords from one machine get HTTP 429
there while a second machine can still log in.

## Nightly scan with a systemd timer

[`systemd/sshbite-scan.service`](systemd/sshbite-scan.service) runs one scan;
[`systemd/sshbite-scan.timer`](systemd/sshbite-scan.timer) starts it every night at 02:30 (with up to
15 min random delay; a missed run is caught up after boot):

```sh
cp docs/systemd/sshbite-scan.service docs/systemd/sshbite-scan.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sshbite-scan.timer
systemctl list-timers sshbite-scan.timer
systemctl start sshbite-scan.service        # run one now
journalctl -u sshbite-scan.service          # the scan's console output and summary
```

- The service fails when the scan exits non-zero: 2 (config), 3 (entry unreachable or pin mismatch –
  investigate before anything else), 4 (internal), 5 (a scan was still running). Partial and unreachable
  hosts do not fail it.
- The UI may run at the same time; it shows the running scan and picks up the result.
- Prefer `NOPASSWD` sudo for unattended scans. If sudo needs a password, put
  `SSHBITE_SUDO_PASSWORD=…` into a root-owned file with mode 0600 and enable the `EnvironmentFile=`
  line of the unit. SSHBITE removes the variable from its environment as soon as it has read it and never
  stores it; the file on disk is yours to protect. The variable is supported but **not recommended**:
  see [the sudo password](#the-sudo-password).

## The sudo password

If sudo on your hosts wants a password, SSHBITE can send one (`--ask-sudo-password`). Read this first:

- **A compromised host can capture it.** SSHBITE runs sudo by its absolute path (`/usr/bin/sudo`, or
  `/bin/sudo` where the first does not exist) and never through the audit account's `PATH`. But an
  attacker with root on a target – the situation after an incident – controls that host's sudo, shell and
  sshd and can imitate a sudo password prompt. SSHBITE then hands it the password.
- **So use a password that is good for nothing else:** set a password that only the audit account
  `sshbite` uses, the same on all hosts or per group, and **rotate it after the scan**. Never use a
  personal or an admin password. `NOPASSWD` sudo for the audit account ([install.md](install.md#sudoers))
  avoids the question entirely.
- **Limit where it goes:** `privilege.password_scope` (CIDRs or host name globs) lists the hosts that may
  receive the password; empty (the default) means every host. A host outside the scope that asks for a
  password is scanned unprivileged and marked partial with *sudo password not sent (outside
  privilege.password_scope)*.
- **How to enter it:** `--ask-sudo-password` prompts on a terminal and refuses when stdin is not one (the
  password could be echoed or logged). In Docker that means `docker exec -it`, not just `-i`.
  `SSHBITE_SUDO_PASSWORD` is supported for unattended runs but **not recommended**: the value stays
  readable in `/proc/<pid>/environ` of the process for its lifetime, and if you pass it with
  `docker run -e` or in a compose file it is shown by `docker inspect`. If you must use it, pass it to
  `docker exec -e` from a root-only `EnvironmentFile` as the nightly unit does, never to the container.

## Docker

The container runs `sshbite serve` (see [install.md](install.md#install-with-docker) and
[compose.example.yaml](compose.example.yaml)); `restart: unless-stopped` brings it back after a reboot.
Everything else runs inside it with `docker exec`:

```sh
docker exec -it sshbite sshbite scan --ask-sudo-password
docker exec sshbite sshbite scans list
docker logs sshbite
```

For the nightly scan use [`systemd/sshbite-scan-docker.service`](systemd/sshbite-scan-docker.service)
(installed as `sshbite-scan.service`) with the same timer. It runs
`docker exec sshbite sshbite scan --label nightly`; with a sudo password it reads it from an
`EnvironmentFile` outside `/etc/sshbite` and passes it with `docker exec -e SSHBITE_SUDO_PASSWORD`, so the
password is never on a command line (see [the sudo password](#the-sudo-password) for the risks).

## UI logins

```sh
sshbite user add NAME        # password prompted twice, at least 12 characters (argon2id)
sshbite user passwd NAME     # new password; ends the user's sessions and clears a lockout
sshbite user remove NAME
printf '%s\n' "$PW" | sshbite user add NAME --password-stdin   # scripts: one line from stdin, no prompt
```

The prompts need a terminal: without one (`docker exec -i`, a pipe) they refuse, because the password
could be echoed. Use `docker exec -it sshbite sshbite user add NAME`, or `--password-stdin` in scripts.

Five failed logins within 15 minutes lock that user for 15 minutes; 20 failures from one address within
15 minutes are answered with HTTP 429. Sessions last `web.session_hours` (8).

## Backup and restore

The database holds every scan, the trusted host keys (TOFU), key labels and the UI logins. Back it up
with SQLite's online backup, which is safe while scans and the UI are running:

```sh
sshbite db backup /var/backups/sshbite/sshbite-$(date +%F).db      # refuses to overwrite; file mode 0600
```

With Docker, write the backup into the data volume and copy it out:

```sh
docker exec sshbite sshbite db backup /data/backup-$(date +%F).db
docker cp sshbite:/data/backup-$(date +%F).db /var/backups/sshbite/
docker exec sshbite rm /data/backup-$(date +%F).db
```

The database is sensitive: it maps who can reach which system with which key. Keep backups as
protected as the database itself. Back up `/etc/sshbite` (config, audit key) separately according to
your policy for secrets.

**Restore:** stop the UI and make sure no scan runs, then replace the database file and remove its
`-wal`/`-shm` files:

```sh
systemctl stop sshbite-serve.service sshbite-scan.timer
cp /var/backups/sshbite/sshbite-2026-11-20.db /var/lib/sshbite/sshbite.db
rm -f /var/lib/sshbite/sshbite.db-wal /var/lib/sshbite/sshbite.db-shm
chown sshbite-app: /var/lib/sshbite/sshbite.db && chmod 600 /var/lib/sshbite/sshbite.db
systemctl start sshbite-serve.service sshbite-scan.timer
```

## Update

1. Read the release notes and take a backup (above).
2. Install the new version:
   - pip: in the new checkout,
     `/opt/sshbite/bin/pip install --require-hashes -r requirements-runtime.lock && /opt/sshbite/bin/pip install --no-deps .`,
     then `systemctl restart sshbite-serve.service`.
   - Docker: `docker build -t sshbite:<new version> .`, set the new tag in your compose file, then
     `docker compose -f compose.example.yaml up -d`.
3. The first `sshbite serve` or `sshbite scan` of the new version migrates the database automatically.
   Before it changes anything it writes a copy next to the database, named after the version doing the
   migration, e.g. `/var/lib/sshbite/sshbite.db.pre-0.2.0` (`/data/sshbite.db.pre-0.2.0` in Docker).
   Without pending migrations nothing is written.
4. Roll back by installing the old version and restoring that `.pre-<version>` file as described under
   *Restore*. Delete the `.pre-` files once the new version works – they contain the same sensitive data.

## Retention

Every scan stays in the database until you delete it. `sshbite scans delete ID` removes a scan and the
hosts and keys no other scan references; key labels of keys still in use are kept. Keep at least the
scans you still want to compare with `sshbite diff`.
