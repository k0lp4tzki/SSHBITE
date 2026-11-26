# Side effects on the audited systems

SSHBITE writes no file on a target – not under `/etc`, `/root` or `/home`, not in `/tmp`, not in any
`known_hosts` (see [review.md](review.md)). But logging in, running sudo and reading files are not
invisible. This page lists everything a scan can leave behind or set off, so you can warn the right
people **before the first real scan**. After a security incident, several of these look exactly like an
attacker moving laterally.

## Tell these people first

| Who | Why |
|---|---|
| **Recipients of sudo mail** (`root` aliases, ticket systems) | sudo can mail a *"SECURITY information for HOST"* report – "This incident has been reported to the administrator" – for every host where sudo refuses or wants a password, on every scan (below). |
| SOC / IDS / EDR operators | SSH from the entry host to every target, a port sweep for CIDR seeds, root reading private keys and `/etc/shadow`. |
| Forensics, if an investigation is running | Reading files can change their access times. |
| Owners of fail2ban / sshguard / CrowdSec | Failed logins of the audit account can get the entry host's address banned. |

## sudo: the "incident" mail on refused sudo

On every host SSHBITE first runs `sudo -n /bin/true` (with `privilege.mode: sudo`; sudo by its absolute
path `/usr/bin/sudo`, or `/bin/sudo` where that does not exist). Whenever sudo
refuses, it may mail a report to `mailto` (default `root`) with the subject
*"\*\*\* SECURITY information for HOST \*\*\*"*, if the host can send mail. Which refusals mail depends on
the sudoers options. Debian and Ubuntu ship `Defaults mail_badpass` in `/etc/sudoers`, and sudo's
`mail_no_user` is on by default. This is what we observed in the lab (Debian 12, sudo 1.9.13, Debian's
default sudoers, mail captured with a test mailer):

| Audit account on the host | What SSHBITE runs | Mail |
|---|---|---|
| `NOPASSWD` rule ([install.md](install.md#sudoers)) | `sudo -n …` | **none** |
| rule that requires a password | `sudo -n /bin/true` (probe) | **yes**: `sshbite : a password is required ; … COMMAND=/bin/true` – on every scan, also when the right password is given afterwards |
| rule that requires a password, wrong `--ask-sudo-password` | `sudo -S -k -p '' /bin/true` | **yes, a second one**: `1 incorrect password attempt` |
| no rule at all | `sudo -n /bin/true` | none (sudo only says "a password is required") |
| no rule at all, and `--ask-sudo-password` is the account's real password | `sudo -S -k -p '' /bin/true` | **yes**: `user NOT in sudoers` (the console says "This incident has been reported to the administrator") |

So a scan can send one or two mails **per host, per scan**; a nightly timer repeats them every night.
Hosts that refuse sudo are scanned unprivileged and marked `partial`. Other options (`mail_no_perms`,
`mail_always`) add mails where they are switched on; other sudo versions and distributions may differ.

To avoid the mails: deploy a `NOPASSWD` rule for the audit account on every host before scanning. If
your policy requires a password, tell the mail recipients when scans run and from which account, or
consider `Defaults:sshbite !mail_badpass` on those hosts (it also hides real password guessing against
this account). With `privilege.mode: none` SSHBITE never calls sudo (all hosts become `partial`).

## Logs written on every scanned host

- **Authentication log / journal** (`/var/log/auth.log`, `/var/log/secure`, `journalctl`): sshd logs the
  login of `sshbite` with the audit key's fingerprint and the source address – the SSHBITE machine for the
  entry host, the entry host (or the previous hop of a chained route) for all others – plus PAM session
  open/close lines. Hosts where the key is not deployed log failed logins instead
  (`Connection closed by authenticating user sshbite … [preauth]`).
- **sudo log** (auth log, journal or sudo's own log file): one line per sudo command, i.e.
  `COMMAND=/bin/true` and `COMMAND=/bin/sh -s` per host, and `incorrect password attempt` for a wrong
  sudo password, plus PAM session lines for root.
- **sudo I/O logging:** if `log_input`/`log_output` is enabled for the account, sudo records the
  collector script and its complete output (authorized_keys contents, file lists, the first character of
  each shadow hash field) under its I/O log directory (e.g. `/var/log/sudo-io`). That directory then holds
  a copy of the inventory – protect or disable it for the audit account. If you scan with a sudo password,
  check whether your sudo version also records it there, or use `NOPASSWD` on such hosts.
- **wtmp / lastlog / utmp:** OpenSSH writes these only for sessions with a terminal. SSHBITE requests no
  terminal, so `last` and `lastlog` normally do not show the audit account. PAM modules in your sshd
  stack (e.g. `pam_lastlog`, `pam_wtmp`) may record the login anyway.
- **auditd / process accounting:** if enabled, every `exec` (`sudo`, `sh`, `cat`, `ssh-keygen`, `sshd -T`,
  …) and every read of watched files such as `/etc/shadow` is recorded.

## Other state outside /etc, /root, /home

- **sudo lecture marker:** after the first *password* sudo, sudo may create `/var/lib/sudo/lectured/sshbite`
  (path differs by distribution). `Defaults:sshbite !lecture` prevents it.
- **sudo timestamp records** in `/run/sudo/ts/` (tmpfs, gone after reboot), depending on sudo version and
  policy. SSHBITE's password commands use `sudo -k`, which tells sudo not to cache the authentication.
- **systemd-logind:** on systemd hosts the login creates a session for `sshbite`, may start its user
  manager (`user@UID.service`) and creates `/run/user/UID`; both disappear when the session ends (unless
  lingering is enabled for the account).
- **Home directory:** SSHBITE writes nothing there. If the account has no home and `pam_mkhomedir` is
  configured, PAM creates one at the first login.

## File access times

The collector reads `authorized_keys`, `known_hosts`, ssh configs, `.pub` files, the first line of private
keys, `/etc/shadow`, `/etc/passwd`, `sshd_config` and more. With the usual `relatime` mount option the
kernel updates a file's **access time** when it is read and the access time was older than its
modification time or more than 24 hours old (not with `noatime`). Modification and change times stay
untouched, and the lab test checks that contents, modes, owners, sizes and mtimes do not change.

If a forensic investigation relies on access times, take its images or timelines **before** scanning, or
tell the investigators which account and time window to ignore.

## Network and security monitoring

- One SSH connection set from the SSHBITE machine to the entry host (`limits.entry_connections`, default
  4); from the entry host, a tunnelled SSH connection to port 22 (or the referenced port) of every
  scanned host – up to `limits.concurrency` (20) at a time. With the chained fallback, intermediate hosts
  forward connections too. To an IDS or NDR this looks like lateral movement from the entry host.
- **CIDR seeds:** every address of `seeds.cidrs` gets a TCP connect from the entry host to the SSH port –
  a port sweep.
- **DNS:** host names are resolved on the entry host with `getent hosts` (and, for names it cannot
  resolve, on the host that referenced them) – DNS queries from those hosts. Hashed `known_hosts` lines
  are matched on the SSHBITE machine without any traffic.
- **EDR rules for credential access:** root running `ssh-keygen -y`/`-l` against private keys and reading
  `/etc/shadow` match common detections (e.g. MITRE ATT&CK T1552.004 *Private Keys*, T1003.008
  */etc/passwd and /etc/shadow*). Expect alerts, or exclude the audit account's session in agreement with
  the SOC.
- **Failed logins and bans:** hosts where the audit key is missing see failed public-key logins from the
  entry host. fail2ban, sshguard or CrowdSec may ban the **entry host's** address – which also locks out
  admins using that jump host. Add the entry host to their ignore lists or deploy the key first.

## Load

Per host: one login, two sudo calls, a few seconds of `sh`, `sshd -T` and one `ssh-keygen` run per
private key found; output is usually well below 1 MB (capped at `limits.max_output_mb`). The entry host
carries all tunnels.

## What SSHBITE does not do

It does not write, create, delete or change files on targets, does not change `known_hosts` on any hop
(no ssh client runs there), does not use keys found on targets, does not forward an agent, and does
not try passwords for SSH logins. The only password it ever sends is the sudo password you give it, to
`sudo -S` on hosts that ask for one and lie inside `privilege.password_scope` (empty = every host).

## The sudo password can be captured by a compromised host

SSHBITE runs sudo by its absolute path, never through the audit account's `PATH`. That does not protect
the password against a host that is already compromised – the reason you are scanning. Root on that host
controls sudo itself, the login shell and sshd, and can imitate a sudo password prompt; SSHBITE then sends
it the password, and it works on every other host that accepts it. Therefore:

- prefer `NOPASSWD` sudo for the audit account ([install.md](install.md#sudoers)) – then no password is sent;
- otherwise give the audit account a password that is **used only by this account**, and **rotate it after
  the scan**;
- limit the hosts that may receive it with `privilege.password_scope`; a host outside the scope that asks
  for a password is scanned unprivileged and marked partial (*sudo password not sent (outside
  privilege.password_scope)*).

More in [operations.md](operations.md#the-sudo-password).

## How this was checked

The lab test checks that `/etc`, `/root` and `/home` of 13 real OpenSSH hosts (Debian 12, OpenSSH 9.2,
sudo 1.9) are byte-identical before and after every scan, and that `sshd -T` and `ssh-keygen` change
nothing on the root filesystem outside `/proc`, `/sys`, `/dev`, `/run` and `/var/log` (see
[review.md](review.md#how-read-only-behaviour-is-tested)). The log entries, mails, access times and
monitoring effects above are not avoidable by SSHBITE. The sudo mails in the table were captured in the
lab with a test mailer (`evidence/p3/sudo-mail-lab-test.txt`); the lab has no real mail transfer agent.
