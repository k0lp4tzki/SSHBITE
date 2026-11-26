# Operations: services, nightly scans, backup, update

Contents: [the UI as a service](#the-ui-as-a-systemd-service) · [nightly scan](#nightly-scan-with-a-systemd-timer) ·
[Docker](#docker) · [UI logins](#ui-logins) · [backup](#backup-and-restore) · [update](#update) ·
[retention](#retention)

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
started with `--tls-cert FILE --tls-key FILE`. The unit is hardened (`ProtectSystem=strict`, only
`/var/lib/sshbite` writable); adjust `ReadWritePaths` if your database lives elsewhere.

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
  stores it; the file on disk is yours to protect.

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
password is never on a command line.

## UI logins

```sh
sshbite user add NAME        # password prompted twice, at least 12 characters (argon2id)
sshbite user passwd NAME     # new password; ends the user's sessions and clears a lockout
sshbite user remove NAME
```

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
     `/opt/sshbite/bin/pip install --require-hashes -r requirements.lock && /opt/sshbite/bin/pip install --no-deps .`,
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
