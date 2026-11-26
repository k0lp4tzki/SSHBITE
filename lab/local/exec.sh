#!/bin/sh
# Run a command as root inside a host of the local lab (all its namespaces), like `docker exec -i`.
#   lab/local/exec.sh a1 sh -s < lab/snapshot.sh
set -eu
h=$1; shift
for pid in $(ip netns pids "sb-$h"); do
  # PID 1 of the host's own PID namespace is its sshd -D
  if awk '/^NSpid:/ {exit !($NF == 1)}' "/proc/$pid/status"; then
    exec nsenter -t "$pid" -m -u -n -p "$@"
  fi
done
echo "host $h is not running" >&2
exit 1
