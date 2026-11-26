#!/bin/sh
# Remove the local lab built by lab/local/up.sh (processes, namespaces, links, bridges, roots).
set -u
L=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "lab/local/down.sh must run as root" >&2; exit 1; }
for p in "$L"/run/*.pid; do
  [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null
done
for ns in $(ip netns list 2>/dev/null | awk '/^sb-/ {print $1}'); do
  for pid in $(ip netns pids "$ns" 2>/dev/null); do kill "$pid" 2>/dev/null; done
  ip netns del "$ns"
done
for n in a b c; do ip link del "sbbr-$n" 2>/dev/null; done
rm -rf "$L/run" "$L/roots"
echo "local lab removed"
