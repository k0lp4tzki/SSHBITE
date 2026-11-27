# Attack matrix (i04): the audit key against the installed gate

Each row is one SSH request with the audit key `lab/keys/audit_ed25519`; a1 is reached through jump,
r1 (AlmaLinux 9, variant A like jump) directly from the scanner.

| Host | Request | Exit | First stderr line / result |
|---|---|---|---|
| jump | `id` | 126 | sshbite-gate: denied (command not allowed) |
| jump | `(login shell, PTY requested)` | - | PTY request refused by sshd: PTY request failed |
| jump | `(login shell, no command)   [stdin: id\nexit]` | 126 | sshbite-gate: denied (command not allowed) |
| jump | `/bin/sh -s   [stdin: id]` | 126 | sshbite-gate: denied (command not allowed) |
| jump | `test -x /usr/bin/sudo && exec /usr/bin/sudo -n /bin/true; exec /bin/sudo -n /bin/true` | 126 | sshbite-gate: denied (command not allowed) |
| jump | `test -x /usr/bin/sudo && exec /usr/bin/sudo -n /bin/sh -s; exec /bin/sudo -n /bin/sh -s   [stdin: id]` | 126 | sshbite-gate: denied (command not allowed) |
| jump | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect; id` | 126 | sshbite-gate: denied (command not allowed) |
| jump | `sudo -n /usr/local/libexec/sshbite/sshbite-collect x` | 126 | sshbite-gate: denied (command not allowed) |
| jump | `sudo -n /bin/sh   [stdin: id]` | 126 | sshbite-gate: denied (command not allowed) |
| jump | `(subsystem sftp)` | 126 | (empty) |
| jump | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 0 | (empty) |
| jump | `sudo -n /usr/local/libexec/sshbite/sshbite-collect   [stdin: id]` | 0 | (empty) |
| jump | `/usr/local/libexec/sshbite/sshbite-resolve   [stdin: a1]` | 0 | (empty) |
| jump | `(direct-tcpip 172.30.1.11:2200)` | - | channel open refused: open failed |
| jump | `(direct-tcpip 172.30.1.11:22)` | 0 | forward opened |
| a1 | `id` | 126 | sshbite-gate: denied (command not allowed) |
| a1 | `(login shell, PTY requested)` | - | PTY request refused by sshd: PTY request failed |
| a1 | `(login shell, no command)   [stdin: id\nexit]` | 126 | sshbite-gate: denied (command not allowed) |
| a1 | `/bin/sh -s   [stdin: id]` | 126 | sshbite-gate: denied (command not allowed) |
| a1 | `test -x /usr/bin/sudo && exec /usr/bin/sudo -n /bin/true; exec /bin/sudo -n /bin/true` | 126 | sshbite-gate: denied (command not allowed) |
| a1 | `test -x /usr/bin/sudo && exec /usr/bin/sudo -n /bin/sh -s; exec /bin/sudo -n /bin/sh -s   [stdin: id]` | 126 | sshbite-gate: denied (command not allowed) |
| a1 | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect; id` | 126 | sshbite-gate: denied (command not allowed) |
| a1 | `sudo -n /usr/local/libexec/sshbite/sshbite-collect x` | 126 | sshbite-gate: denied (command not allowed) |
| a1 | `sudo -n /bin/sh   [stdin: id]` | 126 | sshbite-gate: denied (command not allowed) |
| a1 | `(subsystem sftp)` | 126 | (empty) |
| a1 | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 0 | (empty) |
| a1 | `sudo -n /usr/local/libexec/sshbite/sshbite-collect   [stdin: id]` | 0 | (empty) |
| a1 | `/usr/local/libexec/sshbite/sshbite-resolve   [stdin: a1]` | 0 | (empty) |
| a1 | `(direct-tcpip 172.30.1.12:22)` | - | channel open refused: open failed |
| r1 | `id` | 126 | sshbite-gate: denied (command not allowed) |
| r1 | `(login shell, PTY requested)` | - | PTY request refused by sshd: PTY request failed |
| r1 | `(login shell, no command)   [stdin: id\nexit]` | 126 | sshbite-gate: denied (command not allowed) |
| r1 | `/bin/sh -s   [stdin: id]` | 126 | sshbite-gate: denied (command not allowed) |
| r1 | `test -x /usr/bin/sudo && exec /usr/bin/sudo -n /bin/true; exec /bin/sudo -n /bin/true` | 126 | sshbite-gate: denied (command not allowed) |
| r1 | `test -x /usr/bin/sudo && exec /usr/bin/sudo -n /bin/sh -s; exec /bin/sudo -n /bin/sh -s   [stdin: id]` | 126 | sshbite-gate: denied (command not allowed) |
| r1 | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect; id` | 126 | sshbite-gate: denied (command not allowed) |
| r1 | `sudo -n /usr/local/libexec/sshbite/sshbite-collect x` | 126 | sshbite-gate: denied (command not allowed) |
| r1 | `sudo -n /bin/sh   [stdin: id]` | 126 | sshbite-gate: denied (command not allowed) |
| r1 | `(subsystem sftp)` | 126 | (empty) |
| r1 | `sudo -n -l /usr/local/libexec/sshbite/sshbite-collect` | 0 | (empty) |
| r1 | `sudo -n /usr/local/libexec/sshbite/sshbite-collect   [stdin: id]` | 0 | (empty) |
| r1 | `/usr/local/libexec/sshbite/sshbite-resolve   [stdin: r1]` | 0 | (empty) |
| r1 | `(direct-tcpip 172.30.4.11:2200)` | - | channel open refused: open failed |
| r1 | `(direct-tcpip 172.30.4.11:22)` | 0 | forward opened |
| a1 | `(direct login, no hop)` | - | permission denied: Permission denied for user sshbite on host 172.30.1.11 |

Exit `-`: no process was started - sshd refused the PTY, the forwarding channel or the login itself.
sftp: sshd does not forward a subsystem's stderr; exit 126 is the gate's refusal.
