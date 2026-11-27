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
   test [ true`, plus `ssh-keygen` and `sshd` in fixed forms, `setpriv` in exactly one form (see
   [below](#files-in-user-homes-are-read-as-their-owner)), plus the shell functions defined in the
   script itself (`sec`, `val`, `fhdr`, `uls`, …).
4. **Sections and what they read:**

   | Section | Reads |
   |---|---|
   | META | `hostname`, `uname -srm`, `id -u`, `/etc/os-release` (20 lines), interface addresses (`ip -o addr show`, else `hostname -I`, else `ifconfig -a`) |
   | HOSTKEYS | `/etc/ssh/ssh_host_*_key.pub` |
   | SSHD | `sshd -T` (prints the effective config), `/etc/ssh/sshd_config` and up to 20 files from its `Include` lines |
   | ACCOUNTS | `getent passwd` (max 20,000 lines), else `/etc/passwd` |
   | SHADOW | root only: `awk -F: '{print $1":"substr($2,1,1)":"$8}' /etc/shadow` – the user name, the **first character** of the hash field (`!`, `*`, `$`) and the expiry date. No hash leaves the host. |
   | USERS | **as the account** (`setpriv`, see below), per account with `~/.ssh` or an authorized_keys file (max 2,000): file metadata of every `~/.ssh` entry (max 100); the content of `authorized_keys*` (per `AuthorizedKeysFile`), `known_hosts*`, `config`, `*.pub` (max 5,000 lines, files > 1 MiB skipped) |
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
  exec . source sh bash sudo su xargs env nohup nc socat python python3 perl runuser`;
- `setpriv` in any form other than `setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs --
  CMD` (compared word for word, quotes included), or wrapping anything but `ls stat head test ssh-keygen`
  (whose arguments are then checked by their own rules); a variable as the wrapped command;
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

## Files in user homes are read as their owner

The collector runs as root, but it does not read other users' files as root. Everything it reads below a
user's `~/.ssh` and every `AuthorizedKeysFile` path of that user (also absolute ones such as
`/etc/ssh/authorized_keys/%u`) is read **as that user** – the way sshd itself reads authorized_keys:

- the helpers `uls`, `ustat`, `ulsnd`, `uhead`, `utest` and `ukg` at the top of `collect.sh` run `ls -A`,
  `stat` (and its `ls -lnd` fallback), `head`, `test -r` and `ssh-keygen -y/-l` as
  `setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs -- CMD …` with the account's uid,
  gid and groups from passwd. `setpriv` (util-linux) only switches ids; it opens no PAM session and logs
  nothing. `--no-new-privs` blocks setuid programs. `runuser` and `su` are forbidden by the lint;
- this applies when the collector runs as root and the account's uid is not 0. Root's own home is read
  as root; an unprivileged collector reads everything as itself, as before;
- only the shell tests `[ -L ] [ -d ] [ -f ] [ -e ]` run as root – they look at metadata, never at
  content. HOSTKEYS, SSHD, SHADOW, SYSTEM and META stay root;
- a file the user cannot read (e.g. a root-owned 0600 `authorized_keys2` in the home) is reported as
  `unreadable by account` and shown on the host as the reason `unreadable by account: PATH`; the host
  stays `ok`. sshd cannot use such a file either;
- `ssh-keygen` run by a key's owner refuses a private key that group or others may read ("bad
  permissions", as `ssh` does). Only then the account reads the key once more (`uhead`, at most
  64 KiB) and pipes it to the collector's own `ssh-keygen -y -P '' -f /dev/stdin`. That `ssh-keygen`
  opens no path below `~`, only the pipe, so the race below gains nothing; the key never leaves the host
  and only its public half is printed. Such a key is therefore still reported as *unencrypted* and with
  *bad permissions*. If the key has a passphrase, `ssh-keygen` cannot use the pipe (it opens the key a
  second time to try the passphrase), so for an *encrypted* key that others may read the passphrase
  state is shown as *unknown*; fingerprint and *bad permissions* are still reported. The lint allows `-f /dev/stdin` in exactly this one pipeline
  (`uhead N PATH 2>/dev/null | head -c 65536 | ssh-keygen -y -P "" -f /dev/stdin`);
- **fail closed:** without `/usr/bin/setpriv` (or `/bin/setpriv`) the collector reads nothing in user
  homes – no fallback to root – and the host becomes `partial` with
  `setpriv (util-linux) missing: files in user homes not read`. Host keys, sshd and the shadow summary
  are still collected.

So the old race – a local user swaps a file in their `~/.ssh`, or `~/.ssh` itself, for a symlink to a file
only root may read, between the collector's check and its read – now yields only names, metadata and
content that this user may read anyway. POSIX sh still cannot open a file and check it afterwards, and
the window between `[ -L ]` and the read is still there; it no longer matters.

The lab test `i08_race` (`tests/e2e/test_lab_installed.py`, with `lab/race.sh`) proves it on a Debian 12
and an AlmaLinux 9 host: a local user flips `~/.ssh/known_hosts` between a file and a symlink to a
root-only canary, and `~/.ssh` between the directory and a symlink to a root-only directory, in endless
loops. 200 reads as root (the control) must see the canary at least once; 200 collector runs through the
installed gate must not see it a single time, and at least one of them must have met the swapped state
(`symlink not followed` or `unreadable by account`). The counts are in
`evidence/hardening/race-count.md`.

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
