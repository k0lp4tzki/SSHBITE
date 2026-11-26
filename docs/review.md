# Read-only review guide

SSHBITE must not change the systems it audits. This guide shows a reviewer – without reading the
Python code – exactly what SSHBITE sends to a target, how to check it, and what the automated checks
do and do not guarantee.

## What reaches a target

SSHBITE talks SSH only (asyncssh in the SSHBITE process; no `ssh` client runs anywhere). On a target it
opens **exec channels without a terminal** and runs exactly these command strings – nothing is ever built
from data found on a target:

`sudo` in the table is short for its absolute path: every sudo command is sent as
`test -x /usr/bin/sudo && exec /usr/bin/sudo ARGS; exec /bin/sudo ARGS` – `/usr/bin/sudo`, or `/bin/sudo`
only where the first does not exist. The audit account's `PATH` never decides which `sudo` runs.

| Command | Where | stdin |
|---|---|---|
| `sudo -n /bin/true` | every host (`privilege.mode: sudo`) | – |
| `sudo -n /bin/sh -s` | if the probe succeeded | `collect.sh` |
| `sudo -S -k -p '' /bin/true` | if sudo wants a password, one was given and the host is inside `privilege.password_scope` (empty = all) | the password |
| `sudo -S -k -p '' /bin/sh -s` | if that probe succeeded | the password, then `collect.sh` |
| `/bin/sh -s` | if sudo is not possible (host becomes `partial`) | `collect.sh` |
| `/bin/sh -c '<resolve.sh>'` | entry host (and a referencing host for names the entry cannot resolve) | host names, one per line, as data |

With `privilege.mode: sudo-login` the sudo commands carry `-i`; with `none` only `/bin/sh -s` is used.

### `privilege.mode: installed`

In this mode (recommended, [install.md](install.md#privileges-installed-collector-recommended)) nothing
above is sent. These are the only command strings, P = `privilege.collector_path`
(default `/usr/local/libexec/sshbite/sshbite-collect`):

| Command | Where | stdin |
|---|---|---|
| `sudo -n -l P` | every host: the probe | empty (EOF at once) |
| `sudo -n P` | if the probe succeeded: the installed collector as root | empty (EOF at once) |
| `<dir of P>/sshbite-resolve` | entry host (and a referencing host for names the entry cannot resolve) | host names, one per line, as data |

No script, no `/bin/sh`, no `-S`, no password and no unprivileged fallback. `sudo` stands without a path
here; the gate runs `/usr/bin/sudo` (or `/bin/sudo` where that does not exist). The installed
`sshbite-collect` is `#!/bin/sh` plus `collect.sh` byte for byte; the scan stores the SHA-256 of that file
(`collector sha256` in `sshbite scans show`), the same value as in the export's `SHA256SUMS`. The
collector's first output line carries B as before; a host with a different B is `collector_error`
(*installed collector version differs*).

`sshbite-resolve` is `#!/bin/sh` plus `resolve.sh`: `while IFS= read -r n; do getent hosts -- "$n" | …`.
Each name is read as one line into a variable and only ever passed, quoted and after `--`, as an argument
to `getent` and as an awk variable – never evaluated or executed. SSHBITE also sends only names that match
`[A-Za-z0-9._-]`.

### The gate `sshbite-gate`

The audit key's `authorized_keys` line runs the gate (`command="…/sshbite-gate"`), whatever the client
asks for. It is a short POSIX sh script, written by `sshbite collector export`; read it there. It

- sets `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C` and `umask 077`;
- compares `SSH_ORIGINAL_COMMAND` with `[ "$C" = "…" ]` against exactly the three strings of the table –
  no pattern, no `case`, no `eval`, no `sh -c`;
- runs `exec "$SUDO" -n -l P </dev/null`, `exec "$SUDO" -n P </dev/null` or `exec …/sshbite-resolve`
  (stdin passed through for the names) – the sudo calls get `/dev/null` as stdin, so nothing a client
  sends can reach them;
- refuses everything else – an empty or missing command (interactive login), subsystems such as sftp,
  the commands of the legacy modes, extra arguments, other spacing, appended `; …` – with
  `sshbite-gate: denied (command not allowed)` on stderr and **exit 126**;
- logs every request to syslog `authpriv` (`allowed: probe|collect|resolve`, or `denied: <command>`
  with non-printable characters as `?`, at most 200 characters); a missing syslog does not change the
  result;
- never reads or hashes stdin.

The sudoers file allows the account exactly one command: `sshbite ALL=(root) NOPASSWD: P ""` – P without
arguments. `restrict` in `authorized_keys` disables pty, agent and X11 forwarding; only the entry host (and
hops) may forward, and only to port 22 (`permitopen`). The lab test `tests/e2e/test_lab_installed.py`
(i04) tries a shell with and without pty, `/bin/sh -s` with a script, both legacy sudo commands,
`sudo -n -l P; id`, `sudo -n P x`, `sudo -n /bin/sh`, sftp, a forward to another port and a login from
another address: all are refused.

On the entry host and on hops of a chained route SSHBITE additionally opens `direct-tcpip` channels (port
forwarding) to the next host. It does **not** use the hop's ssh client, so no `known_hosts` file on a hop
is read or written. It never requests a pty, agent forwarding, X11 forwarding, sftp or scp, and it never
uses a key found on a target.

## Print what is sent

```sh
sshbite collector show > collector-review.txt
docker exec sshbite sshbite collector show > collector-review.txt     # Docker
```

The output has three parts:

```
===== collect.sh  sha256 6c262392…40f05  lint: OK
<the complete script>
===== resolve.sh  sha256 f048726e…f2ff  lint: OK
<the complete script>
===== literal commands sent on exec channels (privilege.mode: sudo / sudo-login)
<every command string of the table above>
===== literal commands sent on exec channels (privilege.mode: installed, collector_path /usr/local/libexec/sshbite/sshbite-collect)
<the three command strings of mode installed>
```

The installed files themselves come from `sshbite collector export DIR`; `sshbite-collect` and
`sshbite-resolve` there are the two scripts above with a `#!/bin/sh` line in front.

Review against the installed version: the scripts are part of the package and printed from it.
Every scan stores the SHA-256 of the `collect.sh` it sent – shown by `sshbite scans show ID`
(`collector sha256 …`) and on the scan's page in the UI. If it differs from the hash you reviewed, a
different version was used. The script's second line `B=<12 hex digits>` is the short hash of its body
(a unit test keeps it correct); the collector prints it in its first output line, and SSHBITE marks a host
`collector_error` if that line does not match.

## Reviewing `collect.sh`

Read it top to bottom; it is about 300 lines of POSIX sh. Things to confirm:

1. **The first line** fixes the environment: `LC_ALL=C; export LC_ALL; PATH=/usr/sbin:/usr/bin:/sbin:/bin; set -u`.
2. **Output goes to stdout only.** The only redirections are `2>/dev/null`, `2>&1` and `</dev/null`;
   there is no `>`, `>>` or `tee`, so nothing can be written to a file.
3. **Only reading commands:** `cat head ls stat awk sed grep getent ip hostname uname id sort printf
   test [ true`, plus `ssh-keygen` and `sshd` in fixed forms, plus the shell functions defined in the
   script itself (`sec`, `val`, `fhdr`, …).
4. **Sections and what they read:**

   | Section | Reads |
   |---|---|
   | META | `hostname`, `uname -srm`, `id -u`, `/etc/os-release` (20 lines), interface addresses (`ip -o addr show`, else `hostname -I`, else `ifconfig -a`) |
   | HOSTKEYS | `/etc/ssh/ssh_host_*_key.pub` |
   | SSHD | `sshd -T` (prints the effective config), `/etc/ssh/sshd_config` and up to 20 files from its `Include` lines |
   | ACCOUNTS | `getent passwd` (max 20,000 lines), else `/etc/passwd` |
   | SHADOW | root only: `awk -F: '{print $1":"substr($2,1,1)":"$8}' /etc/shadow` – the user name, the **first character** of the hash field (`!`, `*`, `$`) and the expiry date. No hash leaves the host. |
   | USERS | per account with `~/.ssh` or an authorized_keys file (max 2,000): file metadata of every `~/.ssh` entry (max 100); the content of `authorized_keys*` (per `AuthorizedKeysFile`), `known_hosts*`, `config`, `*.pub` (max 5,000 lines, files > 1 MiB skipped) |
   | private keys | never printed. Only their first line (`-----BEGIN … PRIVATE KEY-----`), `ssh-keygen -y -P '' -f FILE` (prints the **public** key if there is no passphrase; "incorrect passphrase" means encrypted) and `ssh-keygen -l -f FILE` (fingerprint) |
   | SYSTEM | `/etc/ssh/ssh_known_hosts`, `/etc/ssh/ssh_config`, `/etc/ssh/ssh_config.d/*` (max 20) |

5. **Nothing from the target is executed.** File names and file contents are only passed as arguments
   or printed; no `eval`, no `$var` as a command name, no backquotes, no `sh -c "$x"`.

`resolve.sh` is one line: `while IFS= read -r n; do getent hosts -- "$n" | awk …; done`. The names
arrive on stdin and are only ever an argument of `getent hosts`. SSHBITE sends only names matching
`^[A-Za-z0-9._-]{1,253}$`, at most 500 per call.

## What the allowlist lint guarantees

`sshbite/collector/lint.py` checks both scripts statically. It runs in the unit tests (`tests/unit/test_lint.py`,
part of CI) and every time `sshbite collector show` prints a script (`lint: OK` or the violations). It
tokenises the scripts the way a POSIX shell does – quotes, comments, pipelines, lists, `if`/`while`/`case`,
function definitions and `$(…)` command substitutions, recursively – and fails on:

- any command not on the allowlist above (or not a function defined in the script, or one of the
  builtins `set export read continue break return shift :`);
- any of `rm mv cp tee touch mkdir mktemp chmod chown ln dd install truncate ssh scp sftp curl wget eval
  exec . source sh bash sudo su xargs env nohup nc socat python python3 perl`;
- a command name containing `$` (built from data), a command with an unexpected absolute path (only
  `/usr/sbin/sshd` is allowed), background jobs (`&`) and backquotes;
- any redirection other than `2>/dev/null`, `2>&1`, `</dev/null`, and `>>` anywhere;
- arguments outside the fixed forms: `ssh-keygen` only `-y -P "" -f FILE` and `-l -f FILE`; `sshd` only
  `-T`; `sed` only `s/^/|/`; `ip` only `-o addr show`; `hostname` only without arguments or `-I`;
  `ifconfig` only `-a`; `getent` only `passwd` or `hosts`; `sort` without output options; `awk` programs
  without `system()`, `getline`, `close`/`fflush` or `print`/`printf` redirected to a file or pipe.

Tests also feed the lint deliberately bad scripts (`>` files, `sed -i`, `eval`, `$cmd`, `curl`, …) to show it
catches them.

## What the lint does not guarantee

- **It checks the shipped scripts, not the target's binaries.** On a compromised host `cat` or `sudo`
  may be replaced. SSHBITE treats everything it reads as untrusted data (size caps, nothing executed or
  rendered as HTML), but it cannot make a compromised host tell the truth.
- **Allowed commands may have side effects of their own.** `sshd -T` and `ssh-keygen -y/-l` only print,
  which the lab test checks (below). Reading files can update access times; logins and sudo are logged.
  All of this is listed in [side-effects.md](side-effects.md).
- **The literal sudo/sh command strings** are not part of the scripts; they are fixed in
  `sshbite/privilege.py` and printed by `collector show` for review.

## Residual risk: a symlink race in users' `~/.ssh`

The collector runs as root and reads files in directories that belong to other users (`~/.ssh/*`,
authorized_keys files). Before it prints a file it checks that the path is not a symbolic link
(`[ -L "$p" ]`), and for authorized_keys also the directory one level up. POSIX sh offers no way to open a
file first and check the opened file afterwards, so there is a short window between the check and the
read. A local user who owns such a directory could, in that window, replace a file with a symlink to a
file only root may read (e.g. `/etc/shadow`); the collector would then print that content (up to 5,000
lines) into the scan, where it ends up in the database and the UI. The user does not get to see it.

This is accepted as a residual risk and not changed in v1, because:

- only **root and the owner of that home directory** can set up the race – it needs write access to the
  user's own `~/.ssh` at exactly the moment of the scan; root can read the file anyway;
- the content never reaches the attacker: it goes only into the SSHBITE database, which is created with
  mode **0600** in a directory with mode 0700 (and lives in the container's `/data` volume as uid 10001),
  and into the UI, which requires a login;
- the result would be visible: the file would show up as the content of an authorized_keys, config or
  known_hosts file of that user, with parse errors.

If you find such content in a scan, treat that host and user as hostile, delete the scan
(`sshbite scans delete ID`) and its backups.

## Residual risk: the audit key reveals the inventory

Even with `privilege.mode: installed`, whoever holds the audit key and connects from an allowed address
can run the installed collector and read what it prints: every `authorized_keys` line, `known_hosts`,
ssh configs, public keys, `sshd -T` and from `/etc/shadow` only `name:first character:expiry`. That is a
map of who may log in where – valuable to an attacker, but not root: the key gives no shell, no command of
one's own, no root file outside this inventory and no write access. Protect the key accordingly (mode
0600, a dedicated machine, `from=` on every host).

## How read-only behaviour is tested

The lab test (`tests/e2e/test_lab.py`, run in CI against 13 real OpenSSH 9.2 hosts) takes a snapshot of
`/etc`, `/root` and `/home` on every lab host before and after every scan – every path with mode, owner,
size and mtime, plus the SHA-256 of every regular file – and fails unless they are identical. A
separate check (`lab/writecheck.sh`) runs `sshd -T` and `ssh-keygen -y/-l` on lab hosts and confirms
that nothing on the root filesystem changes (outside `/proc`, `/sys`, `/dev`, `/run`, `/var/log`).
