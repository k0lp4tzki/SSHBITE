# sudo stderr on the lab's Debian host (a2) and the resulting SSHBITE message

`Sudo version 1.9.13p3`, requests sent with the audit key through jump and the installed gate.

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
