# Symlink race (i08): control and collector, per host

`lab/race.sh start` on the host: user `racer` flips `~/.ssh/known_hosts` between a file and a symlink to
`/root/race-canary` (0600 root) and `~/.ssh` between the directory and a symlink to `/root/race-dir`
(0700 root, holding `known_hosts` with the same canary), both with `mv -T`, in endless loops.

- **Control**: 200 x `head -n 5 ~racer/.ssh/known_hosts` as root (lab control) - a reader with root's rights; hits = output contains `RACE-CANARY`.
- **Collector**: 200 x `sudo -n /usr/local/libexec/sshbite/sshbite-collect` with the audit key through the installed gate; hits = output contains `RACE-CANARY`.
- **Window hit**: the run printed `symlink not followed` or `unreadable by account` for a path of racer, i.e. it met the swapped state.

| Host | Control (root) | Collector | Collector runs in the window | Complete outputs (#END) | #X reasons for racer (count over all runs) |
|---|---|---|---|---|---|
| r1 | 64/200 | 0/200 | 102/200 | 200/200 | symlink not followed: 40, unreadable by account: 81, vanished while reading: 8 |
| a5 | 77/200 | 0/200 | 102/200 | 200/200 | symlink not followed: 39, unreadable by account: 86, vanished while reading: 1 |
