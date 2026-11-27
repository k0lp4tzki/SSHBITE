# sudo stderr per failure case of spec 4.3 and the resulting SSHBITE message

Requests sent with the audit key through the installed gate (made by `sudo_stderr.py`).

## a2: Debian GNU/Linux 12 (bookworm)

`Sudo version 1.9.13p3`; the lab's Debian 12 host a2, reached through jump.

| Case | Request | Exit | stderr | SSHBITE message (host status collector_error) |
|---|---|---|---|---|
| rule present (reference) | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 0 | (empty) | – |
| rule present (reference) | `sudo -n /usr/local/libexec/sshbite/sshbite-collect` | 0 | (empty) | – |
| missing rule (sshbite has a rule, but not for P) | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 1 | (empty) | privilege.mode installed: sudo does not allow /usr/local/libexec/sshbite/sshbite-collect for this account (sudo -n -l exit 1: ) |
| missing rule (sshbite has a rule, but not for P) | `sudo -n /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: a password is required | (not sent: the probe failed) |
| rule without NOPASSWD | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: a password is required | privilege.mode installed: sudo asks for a password - the sudoers rule for /usr/local/libexec/sshbite/sshbite-collect must be NOPASSWD |
| rule without NOPASSWD | `sudo -n /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: a password is required | (not sent: the probe failed) |
| collector file missing | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: /usr/local/libexec/sshbite/sshbite-collect: command not found | privilege.mode installed: collector not installed at /usr/local/libexec/sshbite/sshbite-collect |
| collector file missing | `sudo -n /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: /usr/local/libexec/sshbite/sshbite-collect: command not found | (not sent: the probe failed) |
| sudoers file missing (no rule for sshbite at all) | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: a password is required | privilege.mode installed: sudo asks for a password - the sudoers rule for /usr/local/libexec/sshbite/sshbite-collect must be NOPASSWD |
| sudoers file missing (no rule for sshbite at all) | `sudo -n /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: a password is required | (not sent: the probe failed) |

## r1: AlmaLinux 9.9 (Chartreuse Bobcat)

`Sudo version 1.9.17p2`; the lab's AlmaLinux 9 host r1, reached directly (variant A).

| Case | Request | Exit | stderr | SSHBITE message (host status collector_error) |
|---|---|---|---|---|
| rule present (reference) | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 0 | (empty) | – |
| rule present (reference) | `sudo -n /usr/local/libexec/sshbite/sshbite-collect` | 0 | (empty) | – |
| missing rule (sshbite has a rule, but not for P) | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 1 | (empty) | privilege.mode installed: sudo does not allow /usr/local/libexec/sshbite/sshbite-collect for this account (sudo -n -l exit 1: ) |
| missing rule (sshbite has a rule, but not for P) | `sudo -n /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: a password is required | (not sent: the probe failed) |
| rule without NOPASSWD | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: a password is required | privilege.mode installed: sudo asks for a password - the sudoers rule for /usr/local/libexec/sshbite/sshbite-collect must be NOPASSWD |
| rule without NOPASSWD | `sudo -n /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: a password is required | (not sent: the probe failed) |
| collector file missing | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: /usr/local/libexec/sshbite/sshbite-collect: command not found | privilege.mode installed: collector not installed at /usr/local/libexec/sshbite/sshbite-collect |
| collector file missing | `sudo -n /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: /usr/local/libexec/sshbite/sshbite-collect: command not found | (not sent: the probe failed) |
| sudoers file missing (no rule for sshbite at all) | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: a password is required | privilege.mode installed: sudo asks for a password - the sudoers rule for /usr/local/libexec/sshbite/sshbite-collect must be NOPASSWD |
| sudoers file missing (no rule for sshbite at all) | `sudo -n /usr/local/libexec/sshbite/sshbite-collect` | 1 | sudo: a password is required | (not sent: the probe failed) |

## Debian vs. EL

The SSHBITE message is the same on both hosts for every case: the mapping of sudo's stderr to the texts of spec 4.3 holds on EL too.
