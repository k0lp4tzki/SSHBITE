# Symlink race (i08): control and collector, per host

`lab/race.sh start` on the host: user `racer` flips `~/.ssh/known_hosts` between a file and a symlink to
`/root/race-canary` (0600 root) and `~/.ssh` between the directory and a symlink to `/root/race-dir`
(0700 root, holding `known_hosts` with the same canary), both with `mv -T`, in endless loops.

- **Control**: 200 x `head -n 5 ~racer/.ssh/known_hosts` as root (lab control) - a reader with root's rights; hits = output contains `RACE-CANARY`.
- **Collector**: 200 x `sudo -n /usr/local/libexec/sshbite/sshbite-collect` with the audit key through the installed gate; hits = output contains `RACE-CANARY`.
- **Window hit**: the run printed `symlink not followed` or `unreadable by account` for a path of racer, i.e. it met the swapped state.

| Host | Control (root) | Collector | Collector runs in the window | Complete outputs (#END) | #X reasons for racer (count over all runs) |
|---|---|---|---|---|---|
| r1 | 71/200 | 0/200 | 121/200 | 200/200 | symlink not followed: 77, unreadable by account: 79, vanished while reading: 2 |
| a5 | 66/200 | 0/200 | 106/200 | 200/200 | symlink not followed: 66, unreadable by account: 70, vanished while reading: 6 |
