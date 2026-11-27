# FIFO race (i09, check-4 finding 1): control and collector, per host

`lab/race.sh start fifo` on the host: user `racer` flips `~/.ssh/known_hosts` between a regular file, a
symlink to `/root/race-canary` (0600 root) and a FIFO that nobody writes, each with `mv -T`, in an endless
loop.

- **Control**: 200 x `head -n 5 ~racer/.ssh/known_hosts` as root, each under `timeout 2`: how many saw the canary, how many blocked on the FIFO (hung).
- **Collector**: 200 x `sudo -n /usr/local/libexec/sshbite/sshbite-collect` with the audit key through the installed gate, 8 at a time, each with a deadline of 30 s; a run that misses it counts as a hang.
- **Left over**: `lab/race.sh procs` right after the runs - every root process whose command line names sudo or sshbite-collect.

| Host | Control: canary | Control: hung | Collector runs | Hangs | Complete (#END) | Canary in output | `read timed out` lines (runs) | Wall time | Root processes left | #X reasons for racer |
|---|---|---|---|---|---|---|---|---|---|---|
| r1 | 83/200 | 41/200 | 200 | 0 | 200/200 | 0 | 3 (3 runs) | 43 s | none | read timed out: 3, symlink not followed: 90, unreadable by account: 42, vanished while reading: 100 |
| a5 | 96/200 | 46/200 | 200 | 0 | 200/200 | 0 | 3 (3 runs) | 24 s | none | read timed out: 3, symlink not followed: 80, unreadable by account: 43, vanished while reading: 93 |
