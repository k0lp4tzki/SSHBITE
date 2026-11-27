# Transcript: running docs/install.md (order A-4971b38d97)

Commands and their real output, per path, from the runs behind the German installation guide
(`docs/install.md`). Long outputs are shortened with `…`; every line that the guide quotes in a
**Prüfung** block is kept.

## How the runs were done

- **Code state.** All runs were on commit `c42fa9d` (the owner's latest code). The commits after it on this
  branch change only `README.md`, `docs/` and this `evidence/` folder (`git diff --stat c42fa9d HEAD -- . ':!docs' ':!README.md'`
  is empty), so the outputs hold for the delivered state.
- **Workspace.** No Docker, no root, no SSH client of its own. SSH tools: openssh-client 10.0p2 (Debian 13
  package, unpacked). Python 3.12.16, Node 22.23.5 (npm 10.9.9), Python 3.13.18 for the second path-C run.
- **Docker.** Docker ran on a separate build host that builds and starts the Docker Compose files committed
  on the branch (it has no host mounts). So `docker build`, `docker compose up/down`, `docker logs` and
  `docker exec` were never typed as such; the same thing happened through that host (details per command).
- **Root on the lab hosts.** Each lab host has a second, lab-only sshd on port 2200 that logs in as root with
  `lab/keys/labctl_ed25519` – the stand-in for "the console as root". The target-host commands of the guide
  were sent there as a shell script with `set -x`, so each command is echoed with a leading `+`.

Labels:

- **literal** – run exactly as written in the guide (placeholders filled in).
- **equivalent** – the same command, but run through the Docker build host, in a second container of the same
  image, with a volume instead of a host directory, as a normal user, or with other paths; what differed is
  said.
- **not run** – not executed. Each such command is marked „nicht getestet“ in `docs/install.md`.

---

## Path A – trying it on the test lab

| Guide command | Label | What differed |
|---|---|---|
| `git clone https://github.com/k0lp4tzki/SSHBITE.git && cd SSHBITE` | equivalent | the branch's working copy instead of a clone from GitHub (public `main` is older) |
| `docker compose -f compose.lab.yaml up -d --build` | equivalent | built and started by the Docker build host from `compose.yaml`, which only `include`s `compose.lab.yaml`; fresh volumes |
| `docker compose -f compose.lab.yaml logs sshbite \| grep 'LAB DEMO LOGIN'` | equivalent | full log of service `sshbite` read through the build host |
| open `http://127.0.0.1:8722/`, log in as `admin` | equivalent | browser (Playwright/Chromium) opened `http://sshbite:8722/`; screenshots `01-pfadA-*` |
| `export SSHBITE_DEMO_PASSWORD=…` | not run | |
| `docker compose -f compose.lab.yaml down -v` | equivalent | stack removed by the build host (containers and volumes) |

Start (twice: at the beginning, and again from commit `2a61a68` before delivery – same result):

```text
From commit 2a61a68217 of your branch. The stack is running: 15 service(s).
  a1: running
  …
  jump: running - http://jump:22 accepts connections (not HTTP)
  r1: running - http://r1:22 accepts connections (not HTTP)
  sshbite: running (healthy) - http://sshbite:8722 answers HTTP 200
```

Log of service `sshbite` (package list shortened):

```text
sshbite-1  | == sshbite config validate --connect
sshbite-1  | config OK: /etc/sshbite/sshbite.yaml
sshbite-1  | warning: config file /etc/sshbite/sshbite.yaml is group- or world-readable (chmod 600 recommended)
sshbite-1  | entry OK, pinned key matches, sudo: root
sshbite-1  | == sshbite user add admin --password-stdin
sshbite-1  | user admin added
sshbite-1  | ################################################################################
sshbite-1  | ## LAB DEMO LOGIN (shown only now):  user admin   password ReXwHfyJggLm5i5iqzvrlXRq
sshbite-1  | ## Test lab only. Set SSHBITE_DEMO_PASSWORD to choose your own.
sshbite-1  | ################################################################################
sshbite-1  | == SSHBITE_SUDO_PASSWORD=*** sshbite scan --label 'lab demo'
sshbite-1  | scan: entry 172.30.1.5:22, max depth 10, max hosts 1000, concurrency 20
sshbite-1  | depth 0: 1 queued, 0 running, 0 done
sshbite-1  | …
sshbite-1  | depth 4: 0 queued, 0 running, 13 done (1 partial, 1 unreachable)
sshbite-1  |
sshbite-1  | scan 1 completed in 16 s
sshbite-1  | hosts:    13 connected; 11 ok, 1 partial, 1 unreachable, 1 excluded, 2 out_of_scope, 1 unresolvable
sshbite-1  | findings: 37 - 4 critical, 15 high, 15 medium, 2 low, 1 info
sshbite-1  | edges:    20 access (19 effective, 3 unknown origin); keys: 10
sshbite-1  | scan id:  1
sshbite-1  | UI:       http://127.0.0.1:8722/  (start it with `sshbite serve`)
sshbite-1  |   id  started               status     hosts  findings  label
sshbite-1  |    1  2026-11-27T08:45:42Z  completed     13        37  lab demo
sshbite-1  | == sshbite serve
sshbite-1  | SSHBITE UI on http://0.0.0.0:8722/  (database /data/sshbite.db)
```

Removal:

```text
The stack is removed.
```

---

## Path B – Docker, `privilege.mode: installed`, against the lab

The Docker build host ran this Compose file (lab-only; not delivered in `docs/`):

```yaml
include:
  - lab/compose.yaml
  - path: [docs/compose.example.yaml, pathb/override.yaml]
services:
  pathb-prep:      # stands in for step 6 on the Docker host: copies key + config into a volume, chown/chmod
    build: .
    user: "0:0"
    entrypoint: ["/bin/sh", "-c", "set -x; cp /src/sshbite.yaml /src/audit_ed25519 /src/audit_ed25519.pub /etc/sshbite/ && chown -R 10001:10001 /etc/sshbite && chmod 700 /etc/sshbite && chmod 600 /etc/sshbite/* && ls -ln /etc/sshbite"]
    volumes: ["./pathb/etc:/src:ro", "pathb-etc:/etc/sshbite"]
    network_mode: none
  pathb-cli:       # stands in for `docker exec sshbite …`: same image, same volumes, same restrictions
    build: .
    depends_on: {sshbite: {condition: service_healthy}}
    entrypoint: ["/bin/sh", "/src/cli.sh"]
    volumes: ["./pathb:/src:ro", "sshbite-data:/data", "pathb-etc:/etc/sshbite:ro"]
    networks: {lab_a: {ipv4_address: 172.30.1.252}}
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
  pathb-d1:        # reproduces the export into a directory that Docker created (troubleshooting row 1)
    build: .
    user: "1000:1000"
    command: ["sshbite", "collector", "export", "/out", "--collector-path", "/usr/local/libexec/sshbite/sshbite-collect"]
    volumes: ["./pathb/not-created-by-mkdir:/out"]
    network_mode: none
volumes:
  pathb-etc:
# pathb/override.yaml – the only change to docs/compose.example.yaml:
services:
  sshbite:
    depends_on:
      pathb-prep: {condition: service_completed_successfully}
      jump: {condition: service_started}
    volumes:
      - pathb-etc:/etc/sshbite:ro        # instead of the host directory /etc/sshbite
    networks:
      lab_a: {ipv4_address: 172.30.1.251}   # attach to the lab network
```

`pathb/cli.sh` ran the guide's `docker exec` commands with `set -x` (shown below as `+ …`).

### Step 1 – build the image

| Guide command | Label | What differed |
|---|---|---|
| `docker build -t sshbite:0.1.0 .` | equivalent | built by the Docker build host from the same `Dockerfile` (`build: .` in `docs/compose.example.yaml`) |
| `docker run --rm sshbite:0.1.0 sshbite --version` | equivalent | in `pathb-cli` (same image) |
| `docker run --rm --entrypoint id sshbite:0.1.0` | equivalent | `id` in `pathb-cli` (same image, default user) |

```text
+ id
uid=10001(sshbite) gid=10001(sshbite) groups=10001(sshbite)
+ sshbite --version
sshbite, version 0.1.0
```

### Step 2 – audit key

| Guide command | Label | What differed |
|---|---|---|
| `install -d -m 700 /etc/sshbite` | equivalent | `/tmp/b/etc-sshbite` as a normal user (no root in the workspace) |
| `ssh-keygen -t ed25519 -N '' -C "sshbite-audit $(date +%F)" -f /etc/sshbite/audit_ed25519` | equivalent | same path difference |
| `ls -l /etc/sshbite` | equivalent | same path difference |

```text
++ install -d -m 700 /tmp/b/etc-sshbite
++ ssh-keygen -t ed25519 -N '' -C 'sshbite-audit 2026-11-27' -f /tmp/b/etc-sshbite/audit_ed25519
Generating public/private ed25519 key pair.
Your identification has been saved in /tmp/b/etc-sshbite/audit_ed25519
Your public key has been saved in /tmp/b/etc-sshbite/audit_ed25519.pub
The key fingerprint is:
SHA256:gTkpsGZgIoI302uV2XE8YPycmXutJsaWQA20ncgZuG4 sshbite-audit 2026-11-27
…
++ ls -l /tmp/b/etc-sshbite
total 8
-rw------- 1 app app 419 Nov 27 08:49 audit_ed25519
-rw-r--r-- 1 app app 106 Nov 27 08:49 audit_ed25519.pub
```

### Step 3 – export the collector, check the checksums

| Guide command | Label | What differed |
|---|---|---|
| `mkdir sshbite-export` | equivalent | `mkdir /tmp/sshbite-export` inside `pathb-cli` |
| `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/sshbite-export:/out" sshbite:0.1.0 sshbite collector export /out --collector-path …` | equivalent | `sshbite collector export /tmp/sshbite-export --collector-path …` in `pathb-cli` (uid 10001, no bind mount); the files used on the targets came from the same command run natively (path C), identical checksums |
| `cd sshbite-export && sha256sum -c SHA256SUMS && cd ..` | literal | (in the container and natively) |
| same `docker run` **without** `mkdir` first (troubleshooting) | equivalent | `pathb-d1`: user 1000, bind mount of a directory Docker created as root |

```text
+ mkdir /tmp/sshbite-export
+ sshbite collector export /tmp/sshbite-export --collector-path /usr/local/libexec/sshbite/sshbite-collect
4000a6adde2ddcaed173b7db08fe71da264a58a458c5356c09ef2ee02d6aa91b  authorized_keys.sshbite
635132805a9f0905786495cfc6b1a1106a0d33b40507a3c67e73dda3558f751b  sshbite-collect
9168d8ef819703916aae627218026663fbcac4f42ef45d11dc648cdbcc071e29  sshbite-gate
99b2af5b9f622e5383068105d58734dfc19417efe0416597f4262a36f124be55  sshbite-resolve
8366ab2a63391d4ca748f6dc480d6d4b40e97342219d4a9269321e63b61ffaac  sudoers.d-sshbite
written to /tmp/sshbite-export - verify with: cd /tmp/sshbite-export && sha256sum -c SHA256SUMS
+ cd /tmp/sshbite-export
+ sha256sum -c SHA256SUMS
authorized_keys.sshbite: OK
sshbite-collect: OK
sshbite-gate: OK
sshbite-resolve: OK
sudoers.d-sshbite: OK
```

The guide shows `written to /out - …` (the mount point of its `docker run`); the line comes from the same
code with the directory argument substituted.

Without `mkdir` first (`pathb-d1`, exit code 4):

```text
pathb-d1-1  | internal error: PermissionError: [Errno 13] Permission denied: '/out/sshbite-collect'
```

Into a non-empty directory (native, exit code 2):

```text
++ sshbite collector export sshbite-export --collector-path /usr/local/libexec/sshbite/sshbite-collect
error: export directory is not empty: sshbite-export
++ echo exit=2
exit=2
```

### Step 4 – prepare the target hosts (jump by hand)

| Guide command | Label | What differed |
|---|---|---|
| `scp -r sshbite-export /etc/sshbite/audit_ed25519.pub root@<HOST>:/root/` | equivalent | as written it **failed** (output below); then `scp -O -P 2200 -i labctl_ed25519 …` to the lab root sshd |
| `cd /root/sshbite-export && sha256sum -c SHA256SUMS` | literal | |
| `id sshbite \|\| useradd -m -s /bin/sh sshbite; passwd -l sshbite` | literal | the account existed in the lab, so `useradd` itself did not run (**not run**) |
| `usermod -s /bin/sh sshbite` | literal | |
| `install -d …/libexec/sshbite`, `install -m 0755 …`, `install -m 0440 … && visudo -cf …` | literal | |
| `chown root:root /home/sshbite && chmod 0755 /home/sshbite`, `install -d … /home/sshbite/.ssh` | literal | |
| `printf 'restrict,port-forwarding,…' '<SCANNER-IP>' "$(cat /root/audit_ed25519.pub)" > …/authorized_keys` (variant A) | literal | `<SCANNER-IP>` = `172.30.1.2,172.30.1.252` |
| `chown root:root …/authorized_keys && chmod 0644 …` | literal | |
| append the `Match User sshbite` block to `/etc/ssh/sshd_config` | equivalent | appended with `printf >>` |
| `sshd -t` | literal | |
| `systemctl reload ssh` | not run | the lab containers have no systemd; `kill -HUP 1` (sshd is PID 1) reloaded the config |
| `sudo -l -U sshbite`, `stat -c '%U %a %n' …`, `command -v setpriv` | literal | |

`scp` as written (plain `scp`, which uses SFTP since OpenSSH 9.0):

```text
++ scp -S /state/home/opt/ssh/usr/bin/ssh -P 2200 -i /state/home/.lab/labctl_ed25519 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR -r sshbite-export /tmp/b/etc-sshbite/audit_ed25519.pub root@172.30.1.5:/root/
subsystem request failed on channel 0
scp: Connection closed
++ echo exit=255
exit=255
```

With `-O` and the commands on jump as root:

```text
++ scp -O -S /state/home/opt/ssh/usr/bin/ssh -P 2200 -i /state/home/.lab/labctl_ed25519 … -r sshbite-export /tmp/b/etc-sshbite/audit_ed25519.pub root@172.30.1.5:/root/
++ echo exit=0
exit=0
+ cd /root/sshbite-export
+ sha256sum -c SHA256SUMS
authorized_keys.sshbite: OK
sshbite-collect: OK
sshbite-gate: OK
sshbite-resolve: OK
sudoers.d-sshbite: OK
+ id sshbite
uid=1000(sshbite) gid=1000(sshbite) groups=1000(sshbite)
+ passwd -l sshbite
passwd: password changed.
+ usermod -s /bin/sh sshbite
usermod: no changes
+ install -d -m 0755 -o root -g root /usr/local/libexec/sshbite
+ install -m 0755 -o root -g root sshbite-collect sshbite-resolve sshbite-gate /usr/local/libexec/sshbite/
+ install -m 0440 -o root -g root sudoers.d-sshbite /etc/sudoers.d/sshbite
+ visudo -cf /etc/sudoers.d/sshbite
/etc/sudoers.d/sshbite: parsed OK
+ chown root:root /home/sshbite
+ chmod 0755 /home/sshbite
+ install -d -m 0755 -o root -g root /home/sshbite/.ssh
+ cat /root/audit_ed25519.pub
+ printf restrict,port-forwarding,permitopen="*:22",permitlisten="localhost:22",from="%s",command="/usr/local/libexec/sshbite/sshbite-gate" %s\n 172.30.1.2,172.30.1.252 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP4zLsa2hUpZvVfg2HzpnjUZ2MV3+YyidkDMdkcBXYKa sshbite-audit 2026-11-27
+ chown root:root /home/sshbite/.ssh/authorized_keys
+ chmod 0644 /home/sshbite/.ssh/authorized_keys
+ printf Match User sshbite\n    AllowTcpForwarding local\n    AllowStreamLocalForwarding no\n
+ sshd -t
+ echo sshd -t OK
sshd -t OK
+ sudo -l -U sshbite
Matching Defaults entries for sshbite on jump:
    env_reset, mail_badpass, secure_path=…, use_pty, …, !lecture, !log_output, !log_input, !requiretty

User sshbite may run the following commands on jump:
    (root) NOPASSWD: /usr/local/libexec/sshbite/sshbite-collect ""
+ stat -c %U %a %n /usr /usr/local /usr/local/libexec /usr/local/libexec/sshbite/sshbite-collect /usr/local/libexec/sshbite/sshbite-gate /usr/local/libexec/sshbite/sshbite-resolve
root 755 /usr
root 755 /usr/local
root 755 /usr/local/libexec
root 755 /usr/local/libexec/sshbite/sshbite-collect
root 755 /usr/local/libexec/sshbite/sshbite-gate
root 755 /usr/local/libexec/sshbite/sshbite-resolve
+ command -v setpriv
/usr/bin/setpriv
+ cat /home/sshbite/.ssh/authorized_keys
restrict,port-forwarding,permitopen="*:22",permitlisten="localhost:22",from="172.30.1.2,172.30.1.252",command="/usr/local/libexec/sshbite/sshbite-gate" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP4zLsa2hUpZvVfg2HzpnjUZ2MV3+YyidkDMdkcBXYKa sshbite-audit 2026-11-27
+ kill -HUP 1
```

(Run three times, because each new start of the lab begins from fresh containers; the three outputs are
identical.)

#### „Ein bereits vorhandenes Konto sshbite“ on jump

| Guide command | Label |
|---|---|
| `getent passwd sshbite \| cut -d: -f7`, `id sshbite`, `ls -la ~sshbite ~sshbite/.ssh`, `ls -A ~sshbite/.ssh`, `ps -u sshbite`, `sshd -T \| grep -Ei …` | literal |
| `crontab -l -u sshbite` | literal (the lab image has no cron: `crontab: not found`) |
| `gpasswd -d sshbite wheel`, `rm -i ~sshbite/.ssh/authorized_keys2` | not run (nothing to remove on jump) |

```text
+ getent passwd sshbite
+ cut -d: -f7
/bin/sh
+ id sshbite
uid=1000(sshbite) gid=1000(sshbite) groups=1000(sshbite)
+ ls -la /home/sshbite /home/sshbite/.ssh
/home/sshbite:
drwxr-xr-x 1 root    root    4096 Nov 26 23:46 .
-rw-r--r-- 1 sshbite sshbite  220 May  7  2026 .bash_logout
-rw-r--r-- 1 sshbite sshbite 3526 May  7  2026 .bashrc
-rw-r--r-- 1 sshbite sshbite  807 May  7  2026 .profile
drwxr-xr-x 1 root    root    4096 Nov 27 08:56 .ssh
/home/sshbite/.ssh:
-rw-r--r-- 1 root root  258 Nov 27 08:56 authorized_keys
+ ls -A /home/sshbite/.ssh
authorized_keys
+ crontab -l -u sshbite
sh: 7: crontab: not found
+ ps -u sshbite
    PID TTY          TIME CMD
+ sshd -T
+ grep -Ei authorizedkeysfile|acceptenv|permituserenvironment
authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
acceptenv LANG
acceptenv LC_*
permituserenvironment no
```

#### The other 12 hosts

| Guide command | Label | What differed |
|---|---|---|
| same commands, variants B and C | equivalent | `lab/installed.sh apply` with the new audit key (same `install`/`visudo`/`printf` steps; variant and `from=` per host from table `AK` in `tests/e2e/test_lab_installed.py`: b3 and c1 variant C, the others B) |

```text
== a1 (B, from=172.30.1.5)
usermod: no changes
/etc/sudoers.d/sshbite: parsed OK
root 755 /usr
root 755 /usr/local
root 755 /usr/local/libexec
root 755 /usr/local/libexec/sshbite
root 755 /usr/local/libexec/sshbite/sshbite-collect
root 755 /usr/local/libexec/sshbite/sshbite-gate
root 755 /usr/local/libexec/sshbite/sshbite-resolve
…   (a2 … b5, c1: the same)
== c2 (B, from=172.30.3.21)
usermod: no changes
/etc/sudoers.d/sshbite: parsed OK
…
```

### Step 5 – pin the entry host key, write the config

| Guide command | Label | What differed |
|---|---|---|
| `ssh-keyscan -t ed25519 -p 22 <ENTRY-HOST> 2>/dev/null \| awk '!/^#/ {print $2" "$3}'` | literal | `<ENTRY-HOST>` = `jump` |
| `ssh-keygen -lf <(ssh-keyscan -t ed25519 -p 22 <ENTRY-HOST> 2>/dev/null)` | literal | bash |
| `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` (console of the entry host) | literal | on jump as root |
| `cat > /etc/sshbite/sshbite.yaml <<'EOF' …` | equivalent | written to `pathb/etc/sshbite.yaml` (then copied into the volume by `pathb-prep`) and to `/tmp/b/etc-sshbite/sshbite.yaml` for path C |

First version of the awk (without `!/^#/`) printed the comment line that OpenSSH 10.0 writes to stdout –
the reason for the filter now in the guide:

```text
+ ssh-keyscan -t ed25519 -p 22 jump
+ awk '{print $2" "$3}'
jump:22 SSH-2.0-OpenSSH_9.2p1
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID/sbq+Iimhi7je22+U9y15jJ/37+NCH06PcVShHSmh/
```

As in the guide:

```text
+ ssh-keyscan -t ed25519 -p 22 jump
+ awk '!/^#/ {print $2" "$3}'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID/sbq+Iimhi7je22+U9y15jJ/37+NCH06PcVShHSmh/
+ ssh-keygen -lf /dev/fd/63
++ ssh-keyscan -t ed25519 -p 22 jump
256 SHA256:ynTb0gWnV8EppDctYzEhTtbjMnfZ2636k864CRGdTDg jump (ED25519)
```

On jump as root:

```text
+ ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
256 SHA256:ynTb0gWnV8EppDctYzEhTtbjMnfZ2636k864CRGdTDg root@jump (ED25519)
```

The config as the container read it:

```text
+ cat /etc/sshbite/sshbite.yaml
database: /data/sshbite.db          # Pfad C: /var/lib/sshbite/sshbite.db
entry:
  host: 172.30.1.5
  port: 22
  host_keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID/sbq+Iimhi7je22+U9y15jJ/37+NCH06PcVShHSmh/"]
audit:
  user: sshbite
  key_file: /etc/sshbite/audit_ed25519
privilege:
  mode: installed
  collector_path: /usr/local/libexec/sshbite/sshbite-collect
crawl:
  include: [172.30.1.0/24, 172.30.2.0/24, 172.30.3.0/24]   # leer = keine Einschränkung (mit Warnung)
```

Pin with the host name in front (native, exit code 2) and wrong pin (exit code 3):

```text
++ sshbite -c c2.yaml config validate --connect
error: c2.yaml: entry.host_keys[0]: not an OpenSSH public key line ('<alg> <base64> [comment]', e.g. from ssh-keyscan)
++ echo exit=2
exit=2
++ sshbite -c c3.yaml scan --label mismatch
scan: entry jump:22, max depth 10, max hosts 1000, concurrency 20
error: ENTRY HOST KEY MISMATCH – scan aborted
  offered by jump:22: ssh-ed25519 SHA256:ynTb0gWnV8EppDctYzEhTtbjMnfZ2636k864CRGdTDg
  pinned: ssh-ed25519 SHA256:A3ZcCoVAi6MU3LodydM/OT0egxdhDBAMGsPlXEwcOCA
++ echo exit=3
exit=3
++ sshbite -c c4.yaml config validate
error: entry.host_keys: missing - pin the entry host key (scan aborts without it)
++ echo exit=2
exit=2
```

### Step 6 – give the files to the container user

| Guide command | Label | What differed |
|---|---|---|
| `chown -R 10001:10001 /etc/sshbite && chmod 700 /etc/sshbite && chmod 600 /etc/sshbite/*` | equivalent | in `pathb-prep` as root on the volume `pathb-etc` |
| `ls -ln /etc/sshbite` | equivalent | same |

```text
pathb-prep-1  | + cp /src/sshbite.yaml /src/audit_ed25519 /src/audit_ed25519.pub /etc/sshbite/
pathb-prep-1  | + chown -R 10001:10001 /etc/sshbite
pathb-prep-1  | + chmod 700 /etc/sshbite
pathb-prep-1  | + chmod 600 /etc/sshbite/audit_ed25519 /etc/sshbite/audit_ed25519.pub /etc/sshbite/sshbite.yaml
pathb-prep-1  | + ls -ln /etc/sshbite
pathb-prep-1  | total 12
pathb-prep-1  | -rw------- 1 10001 10001 419 Nov 27 08:59 audit_ed25519
pathb-prep-1  | -rw------- 1 10001 10001 106 Nov 27 08:59 audit_ed25519.pub
pathb-prep-1  | -rw------- 1 10001 10001 471 Nov 27 08:59 sshbite.yaml
```

### Step 7 – start the container

| Guide command | Label | What differed |
|---|---|---|
| `docker compose -f docs/compose.example.yaml up -d` | equivalent | `docs/compose.example.yaml` plus `pathb/override.yaml` (volume instead of `/etc/sshbite`, lab network) |
| `docker ps` shows `(healthy)` | equivalent | status from the build host |
| `docker logs sshbite` | equivalent | log of service `sshbite` |
| `docker run -d --name sshbite …` (without Compose) | not run | |

```text
  sshbite: running (healthy) - http://sshbite:8722 answers HTTP 200
sshbite-1  | SSHBITE UI on http://0.0.0.0:8722/  (database /data/sshbite.db)
sshbite-1  | no UI user yet - create one with `sshbite user add NAME`
```

### Step 8 – validate the connection

| Guide command | Label | What differed |
|---|---|---|
| `docker exec -it sshbite sshbite config validate --connect` | equivalent | in `pathb-cli` (second container, same image and volumes, address 172.30.1.252); it first waited until jump accepted the key (loop shortened) |

```text
+ sshbite config validate --connect
config OK: /etc/sshbite/sshbite.yaml
entry OK, pinned key matches, sudo: root (installed /usr/local/libexec/sshbite/sshbite-collect, collector B=386f9faea780 matches)
+ echo exit=0
exit=0
```

### Step 9 – UI user

| Guide command | Label | What differed |
|---|---|---|
| `docker exec -it sshbite sshbite user add admin` (interactive prompt) | not run | no terminal available |
| `printf '%s\n' "$PW" \| docker exec -i sshbite sshbite user add admin --password-stdin` | equivalent | in `pathb-cli` |
| interactive form without a terminal (troubleshooting) | equivalent | in `pathb-cli`, stdin `/dev/null` |

```text
+ printf %s\n pfad-b-admin-2026
+ sshbite user add admin --password-stdin
user admin added
+ echo exit=0
exit=0
+ sshbite user add admin2
Usage: sshbite user add [OPTIONS] NAME
Try 'sshbite user add --help' for help.

Error: refusing to read the password: stdin is not a terminal, so the password could be echoed or logged. Run it in a terminal - in a container with `docker exec -it` (not just -i), or pipe it with --password-stdin.
+ echo exit=2
exit=2
```

### Step 10 – first scan

| Guide command | Label | What differed |
|---|---|---|
| `docker exec sshbite sshbite scan --label first` | equivalent | in `pathb-cli` |
| `docker exec sshbite sshbite scans list` | equivalent | in `pathb-cli` |
| `--ask-sudo-password` in installed mode (troubleshooting) | equivalent | in `pathb-cli` |

```text
+ sshbite scan --label first
scan: entry 172.30.1.5:22, max depth 10, max hosts 1000, concurrency 20
depth 0: 1 queued, 0 running, 0 done
…
depth 4: 0 queued, 0 running, 14 done (1 unreachable)

scan 1 completed in 22 s
hosts:    14 connected; 13 ok, 1 unreachable, 2 out_of_scope, 1 unresolvable
findings: 36 - 4 critical, 16 high, 13 medium, 2 low, 1 info
edges:    21 access (20 effective, 4 unknown origin); keys: 11
scan id:  1
UI:       http://127.0.0.1:8722/  (start it with `sshbite serve`)
+ echo exit=0
exit=0
+ sshbite scans list
  id  started               status     hosts  findings  label
   1  2026-11-27T09:04:16Z  completed     14        36  first
+ sshbite scan --ask-sudo-password
error: privilege.mode installed never sends a sudo password - remove --ask-sudo-password
+ echo exit=2
exit=2
```

### Step 11 – open the UI

| Guide command | Label | What differed |
|---|---|---|
| open `http://127.0.0.1:8722/`, log in | equivalent | Chromium opened `http://sshbite:8722/` (the published port is not reachable from the workspace); screenshots `02-pfadB-docker-installed-*` (login, dashboard, heatmap, hosts) |
| `ssh -L 8722:127.0.0.1:8722 <ADMIN>@<SCANNER>` | not run | |

### Wrong database path (troubleshooting)

Equivalent: in `pathb-cli` with a copy of the config whose `database:` is `/var/lib/sshbite/sshbite.db`.

```text
+ sshbite -c /tmp/wrongdb.yaml scan --no-crawl --label wrongdb
internal error: OSError: [Errno 30] Read-only file system: '/var/lib/sshbite'
+ echo exit=4
exit=4
```

### Key file with mode 0644 (troubleshooting)

Equivalent: native (path C install), copy of the key with `chmod 644`.

```text
++ sshbite -c c1.yaml config validate
error: audit.key_file: /tmp/ts/k644: mode is 0644, must be 0600 (chmod 600 /tmp/ts/k644)
++ echo exit=2
exit=2
```

### Entry host key not pinned (troubleshooting, added after QA check-3)

Equivalent: native, as a normal user, on this branch (code unchanged since `c42fa9d`), Python
3.12 venv from `requirements-runtime.lock`, `sshbite.cli:main` run directly. Config from `init-config` with
the `host_keys:` line removed, `entry.host: 172.30.1.5` (no lab reachable; the scan stops before connecting).

```text
+ sshbite --config c2.yaml config validate
warning: config file /tmp/repro/c2.yaml is group- or world-readable (chmod 600 recommended)
warning: crawl.include is empty: …
error: entry.host_keys: missing - pin the entry host key (scan aborts without it)
exit=2
+ sshbite --config c2.yaml scan
warning: crawl.include is empty: …
scan: entry 172.30.1.5:22, max depth 10, max hosts 1000, concurrency 20
error: ENTRY HOST KEY NOT PINNED - scan aborted: set entry.host_keys in the config
exit=3
+ sshbite --config c2.yaml scans list
  id  started               status     hosts  findings  label
   1  2026-11-27T09:27:51Z  aborted        0         0  
exit=0
```

The aborted scan takes a scan ID (here 1); the next successful scan would be 2. This backs the note in
install.md Schritt 10.

### Which address is `unreachable` in step 10

Not re-run. In the step-10 output `14 connected; 13 ok, 1 unreachable`, the 13 `ok` hosts are the 13 prepared
lab hosts (jump, a1–a5, b1–b5, c1, c2; r1 was not prepared and is not reached). The unreachable address is
`172.30.1.99`: `lab/expected.yaml` lists it as `unreachable`, found in `a2 /home/deploy/.ssh/known_hosts:1`, and
no lab container has that address (`lab/compose.yaml`).

---

## Update (guide section „Aktualisierung“)

| Guide command | Label | What differed |
|---|---|---|
| `install -d -m 700 /var/backups/sshbite` | not run | |
| `docker exec sshbite sshbite db backup /data/backup-$(date +%F).db` | equivalent | in `pathb-cli` on the volume `sshbite-data` |
| `docker cp …`, `docker exec sshbite rm …` | not run | |
| `git pull` | not run | |
| `docker build -t sshbite:<NEW-VERSION> .` + `docker compose -f docs/compose.example.yaml up -d` | equivalent | the image was rebuilt from newer commits of the branch (still 0.1.0) and the stack started again, several times; each start began with empty volumes, so the database migration and its `.pre-<VERSION>` copy were **not** observed |
| `diff sshbite-export/SHA256SUMS sshbite-export-<NEW-VERSION>/SHA256SUMS` | not run | no new version exists |
| `install -m 0755 … sshbite-collect …` on the targets | literal as part of step 4; as an update not run | |
| `docker exec -it sshbite sshbite config validate --connect` | equivalent | after each rebuild, in `pathb-cli` (same output as step 8) |
| `docker exec sshbite sshbite scan --label after-update` | not run with this label | the scan of step 10 ran after each rebuild |

```text
+ sshbite db backup /data/backup-2026-11-27.db
backup written to /data/backup-2026-11-27.db
+ echo exit=0
exit=0
+ ls -l /data
total 776
-rw------- 1 sshbite sshbite 397312 Nov 27 09:04 backup-2026-11-27.db
-rw------- 1 sshbite sshbite 397312 Nov 27 09:04 sshbite.db
```

---

## Uninstall (guide section „Deinstallation“)

### Scanner machine, path B

| Guide command | Label | What differed |
|---|---|---|
| `docker compose -f docs/compose.example.yaml down -v` | equivalent | the build host removed the whole stack with its volumes |
| `docker image rm sshbite:0.1.0` | not run | |
| `rm -r /etc/sshbite` | not run | in the lab it was the volume `pathb-etc`, removed by `down -v` |

```text
The stack is removed.
```

### Scanner machine, path C

Not run (marked „nicht getestet“ in the guide).

### Target host a1

| Guide command | Label |
|---|---|
| `rm /etc/sudoers.d/sshbite`, `rm -r /usr/local/libexec/sshbite`, `rm /home/sshbite/.ssh/authorized_keys` | literal (as root on a1) |
| `userdel -r sshbite` | literal |
| `rm -r /home/sshbite` | not run |
| `rm -r /root/sshbite-export /root/audit_ed25519.pub` | not run (a1 was prepared with `lab/installed.sh`, which leaves no such files) |
| remove the `Match` block and reload sshd | not run (a1 is a variant-B host without the block) |
| `sudo -l -U sshbite`, `id sshbite` (checks) | literal |

```text
+ rm /etc/sudoers.d/sshbite
+ rm -r /usr/local/libexec/sshbite
+ rm /home/sshbite/.ssh/authorized_keys
+ sudo -l -U sshbite
User sshbite is not allowed to run sudo on a1.
+ ls /usr/local/libexec/sshbite /home/sshbite/.ssh/authorized_keys
ls: cannot access '/usr/local/libexec/sshbite': No such file or directory
ls: cannot access '/home/sshbite/.ssh/authorized_keys': No such file or directory
+ userdel -r sshbite
userdel: sshbite mail spool (/var/mail/sshbite) not found
userdel: /home/sshbite not owned by sshbite, not removing
+ id sshbite
id: 'sshbite': no such user
```

Next scan (native, path C install):

```text
scan 3 completed in 22 s
hosts:    9 connected; 8 ok, 1 auth_failed, 2 out_of_scope, 1 unresolvable
…
a1                 auth_failed       -                 1  jump /home/ops/.ssh/config:2                 -
                    tried jump -> a1: 172.30.1.11: authentication failed: Permission denied for user sshbite on host 172.30.1.11
```

---

## Path C – native with pip

### Python 3.12

| Guide command | Label | What differed |
|---|---|---|
| `useradd --system … sshbite-app`, `install -d … /var/lib/sshbite` | not run | no root |
| `git clone https://github.com/k0lp4tzki/SSHBITE.git /opt/sshbite-src` | equivalent | `git clone` of the branch into `/tmp/c/src` |
| `python3.12 -m venv /opt/sshbite` | equivalent | `/tmp/c/opt-sshbite` |
| `/opt/sshbite/bin/pip install --require-hashes -r requirements-runtime.lock` | equivalent | same path difference (`-q`) |
| `/opt/sshbite/bin/pip install --no-deps .` | equivalent | same path difference |
| `ln -s /opt/sshbite/bin/sshbite /usr/local/bin/sshbite` | not run | venv `bin` on `PATH` instead |
| `sshbite --version` | literal | |
| `mkdir sshbite-export`, `sshbite collector export sshbite-export --collector-path …`, `cd sshbite-export && sha256sum -c SHA256SUMS && cd ..` | literal | |
| `chown -R sshbite-app:sshbite-app /etc/sshbite …` | not run | `chmod 700`/`chmod 600` on `/tmp/b/etc-sshbite` as the normal user |
| `sudo -u sshbite-app sshbite config validate --connect` / `user add` / `scan --label first` | equivalent | as the normal user, with `-c /tmp/b/etc-sshbite/sshbite.yaml`; `user add` with `--password-stdin` |
| `cp docs/systemd/sshbite-serve.service …`, `systemctl daemon-reload && systemctl enable --now …` | not run | no systemd; `sshbite serve` started by hand instead |
| `pip wheel --no-deps -w dist .` / install of the wheel | not run | |

```text
++ python3.12 --version
Python 3.12.16
++ node --version
v22.23.5
++ npm --version
10.9.9
++ git clone -q -b package/A-4971b38d97/P-05376d4737 /workspace /tmp/c/src
++ cd /tmp/c/src
++ git log --oneline -1
c42fa9d securutiy-hardening (A-ef5350a11f) released by the owner
++ python3.12 -m venv /tmp/c/opt-sshbite
++ /tmp/c/opt-sshbite/bin/pip install -q --require-hashes -r requirements-runtime.lock
++ echo exit=0
exit=0
++ /tmp/c/opt-sshbite/bin/pip install --no-deps .
…
Successfully built sshbite
Installing collected packages: sshbite
Successfully installed sshbite-0.1.0
++ echo exit=0
exit=0
++ /tmp/c/opt-sshbite/bin/sshbite --version
sshbite, version 0.1.0
```

Export (the files that went to the targets):

```text
++ mkdir sshbite-export
++ sshbite collector export sshbite-export --collector-path /usr/local/libexec/sshbite/sshbite-collect
4000a6adde2ddcaed173b7db08fe71da264a58a458c5356c09ef2ee02d6aa91b  authorized_keys.sshbite
635132805a9f0905786495cfc6b1a1106a0d33b40507a3c67e73dda3558f751b  sshbite-collect
9168d8ef819703916aae627218026663fbcac4f42ef45d11dc648cdbcc071e29  sshbite-gate
99b2af5b9f622e5383068105d58734dfc19417efe0416597f4262a36f124be55  sshbite-resolve
8366ab2a63391d4ca748f6dc480d6d4b40e97342219d4a9269321e63b61ffaac  sudoers.d-sshbite
written to sshbite-export - verify with: cd sshbite-export && sha256sum -c SHA256SUMS
++ cd sshbite-export
++ sha256sum -c SHA256SUMS
authorized_keys.sshbite: OK
sshbite-collect: OK
sshbite-gate: OK
sshbite-resolve: OK
sudoers.d-sshbite: OK
```

Validate, user, scan, serve:

```text
++ sshbite -c /tmp/b/etc-sshbite/sshbite.yaml config validate
config OK: /tmp/b/etc-sshbite/sshbite.yaml
++ echo exit=0
exit=0
++ sshbite -c /tmp/b/etc-sshbite/sshbite.yaml config validate --connect
config OK: /tmp/b/etc-sshbite/sshbite.yaml
entry OK, pinned key matches, sudo: root (installed /usr/local/libexec/sshbite/sshbite-collect, collector B=386f9faea780 matches)
++ echo exit=0
exit=0
++ printf '%s\n' pfad-c-admin-2026
++ sshbite -c /tmp/b/etc-sshbite/sshbite.yaml user add admin --password-stdin
user admin added
++ sshbite -c /tmp/b/etc-sshbite/sshbite.yaml scan --label first
scan: entry jump:22, max depth 10, max hosts 1000, concurrency 20
…
scan 2 completed in 22 s
hosts:    14 connected; 13 ok, 1 unreachable, 2 out_of_scope, 1 unresolvable
findings: 36 - 4 critical, 16 high, 13 medium, 2 low, 1 info
edges:    21 access (20 effective, 4 unknown origin); keys: 11
scan id:  2
++ sshbite -c /tmp/b/etc-sshbite/sshbite.yaml scans list
  id  started               status     hosts  findings  label
   1  2026-11-27T08:57:21Z  aborted        0         0  mismatch
   2  2026-11-27T08:57:31Z  completed     14        36  first
++ ls -l /tmp/c/var
-rw------- 1 app app 409600 Nov 27 08:57 sshbite.db
```

`sshbite serve` (by hand, not through systemd; database path from that run's config):

```text
SSHBITE UI on http://127.0.0.1:8722/  (database /tmp/c/var/sshbite.db)
```

Screenshots `03-pfadC-nativ-*`.

### Python 3.13

Equivalent (venv in `/tmp/c313`, `pip -q`):

```text
++ /usr/local/bin/python3 --version
Python 3.13.18
++ /tmp/c313/bin/pip install -q --require-hashes -r requirements-runtime.lock
++ echo exit=0
exit=0
++ /tmp/c313/bin/pip install -q --no-deps .
++ echo exit=0
exit=0
++ /tmp/c313/bin/sshbite --version
sshbite, version 0.1.0
++ /tmp/c313/bin/sshbite -c /tmp/b/etc-sshbite/sshbite.yaml config validate --connect
config OK: /tmp/b/etc-sshbite/sshbite.yaml
entry OK, pinned key matches, sudo: root (installed /usr/local/libexec/sshbite/sshbite-collect, collector B=386f9faea780 matches)
++ echo exit=0
exit=0
```

### Without npm (troubleshooting)

Equivalent: `pip install --no-deps .` in a scratch environment without npm (as saved, two attempts; the
first lacked setuptools, the second shows the message the guide quotes):

```text
  error: backend-unavailable
  ╰─> ModuleNotFoundError: No module named 'setuptools'
error: metadata-generation-failed
× Encountered error while generating package metadata.
      frontend/ is not built and npm is not available: install Node 22 or build it first
```

---

## Tests

Unit and web tests (not e2e), on `c42fa9d`; label: literal.

```text
$ cd frontend && npm ci --no-audit --no-fund && npm run build
$ python -m pytest tests/unit tests/web -m "not e2e" -q -rs
…
346 passed in 65.77s (0:01:05)
```

No test reads documentation text: the only mentions of `docs/` in `tests/` and `sshbite/` are comments and
help strings (`tests/e2e/test_lab_installed.py` lines 4, 372, 414; `sshbite/config.py:33`;
`sshbite/web/cli.py:56`).

`tests/e2e/test_lab_installed.py` against the running lab; label: literal.

```text
$ SSHBITE_LAB_NO_START=1 SSHBITE_LAB_ENTRY=jump:22 python -m pytest -m e2e tests/e2e/test_lab_installed.py -v -rs
platform linux -- Python 3.12.16, pytest-9.2.0, pluggy-1.7.0
collected 12 items
tests/e2e/test_lab_installed.py::test_i00_sudo_baseline PASSED           [  8%]
tests/e2e/test_lab_installed.py::test_i01_apply PASSED                   [ 16%]
tests/e2e/test_lab_installed.py::test_i02_validate PASSED                [ 25%]
tests/e2e/test_lab_installed.py::test_i03_scan_installed PASSED          [ 33%]
tests/e2e/test_lab_installed.py::test_i04_attack_matrix PASSED           [ 41%]
tests/e2e/test_lab_installed.py::test_i05_failures PASSED                [ 50%]
tests/e2e/test_lab_installed.py::test_i06_r1 PASSED                      [ 58%]
tests/e2e/test_lab_installed.py::test_i07_no_setpriv PASSED              [ 66%]
tests/e2e/test_lab_installed.py::test_i08_race PASSED                    [ 75%]
tests/e2e/test_lab_installed.py::test_i09_fifo_race PASSED               [ 83%]
tests/e2e/test_lab_installed.py::test_i10_flood PASSED                   [ 91%]
tests/e2e/test_lab_installed.py::test_i99_remove PASSED                  [100%]
======================== 12 passed in 449.32s (0:07:29) ========================
```

The browser tests (`tests/browser`) were skipped: Playwright's Python package is not installed in the test
environment (`1 skipped`).

---

## Link check

Script: [`linkcheck.py`](linkcheck.py) (next to this file). It checks every relative link in `README.md` and
`docs/*.md`, outside code blocks and inline code: the file must exist, and an anchor must be a heading slug
by GitHub's rules or an `<a id>` in the target file. Label: literal, run on the delivered commit.

```text
$ python3 evidence/install-guide/linkcheck.py .
140 relative links checked, 0 broken, 0 via legacy anchors only
```

(139 links at the first delivery; the correction added one link from the `scp` note in install.md to the
troubleshooting table.)
