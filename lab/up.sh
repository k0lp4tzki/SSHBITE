#!/bin/sh
# Start the SSHBITE test lab and render lab/sshbite.lab.yaml (spec 9.2).
#
#   lab/up.sh                 start with docker (else podman, else the root fallback lab/local/up.sh)
#   LAB_NO_START=1 lab/up.sh  only render the config (the lab is already running elsewhere)
#   LAB_ENTRY_HOST / LAB_ENTRY_PORT  where the jump host answers (default 127.0.0.1:2222)
set -eu
LAB=$(cd "$(dirname "$0")" && pwd)
RUN="$LAB/.run"
ENTRY_HOST=${LAB_ENTRY_HOST:-127.0.0.1}
ENTRY_PORT=${LAB_ENTRY_PORT:-2222}
mkdir -p "$RUN"
chmod 700 "$RUN"
cp "$LAB/keys/audit_ed25519" "$RUN/audit_ed25519"
chmod 600 "$RUN/audit_ed25519"
PIN=$(cut -d' ' -f1-2 "$LAB/keys/jump_host_ed25519.pub")
umask 077
cat > "$LAB/sshbite.lab.yaml" <<YAML
# Rendered by lab/up.sh - the lab's SSHBITE config (spec 9.2). Only the entry point is configured.
database: $RUN/sshbite.db
entry:
  host: $ENTRY_HOST
  port: $ENTRY_PORT
  host_keys: ["$PIN"]
audit:
  user: sshbite
  key_file: $RUN/audit_ed25519
crawl:
  include: [172.30.1.0/24, 172.30.2.0/24, 172.30.3.0/24]
  exclude: [172.30.2.14/32]
limits:
  connect_timeout: 5
rules:
  many_hosts_threshold: 5
YAML
echo "config: $LAB/sshbite.lab.yaml"

if [ "${LAB_NO_START:-}" = 1 ]; then
  exit 0
fi
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker compose -f "$LAB/compose.yaml" up -d --build --wait
elif command -v podman >/dev/null 2>&1; then
  podman compose -f "$LAB/compose.yaml" up -d --build
elif [ "$(id -u)" = 0 ]; then
  sh "$LAB/local/up.sh"
else
  echo "lab unavailable: need docker, podman or root" >&2
  exit 1
fi
i=0
until python3 -c "import socket,sys; socket.create_connection(('$ENTRY_HOST', $ENTRY_PORT), 2).close()" 2>/dev/null; do
  i=$((i + 1))
  if [ $i -gt 60 ]; then echo "entry $ENTRY_HOST:$ENTRY_PORT does not answer" >&2; exit 1; fi
  sleep 1
done
echo "lab is up: entry $ENTRY_HOST:$ENTRY_PORT"
