#!/bin/sh
# SSHBITE lab without a container runtime (spec 9.2, fallback 2). Run as root on a Linux machine with
# openssh-server, sudo, iproute2, util-linux (unshare, nsenter) and socat installed.
#
# It builds the same 13 hosts as lab/compose.yaml:
#   - one network namespace per host (sb-<host>), veth pairs into three bridges on the lab subnets
#     (sbbr-a 172.30.1.0/24, sbbr-b 172.30.2.0/24, sbbr-c 172.30.3.0/24); no default routes, so jump
#     cannot reach lab_c, exactly as in compose
#   - one mount/UTS/PID namespace per host: a per-host copy of /etc and empty /root, /home, /var/backups
#     and /lab, prepared by the very same lib.sh + seed/<host>/setup.sh as the image build
#   - in each host: the lab-control sshd (port 2200) and `sshd -D` as PID 1, like the container entrypoint
#   - socat forwarding 127.0.0.1:2222 to jump:22
# The real collector runs unchanged against real sshd; snapshots work through the lab-control sshd
# (tests/e2e) or `lab/local/exec.sh HOST sh -s < lab/snapshot.sh` (nsenter).
#
# Everything lives under lab/local/roots and lab/local/run; lab/local/down.sh removes it all.
# The only change outside the repository is the empty mount point /lab (created if missing).
#
# STATUS: written for the spec, not executed in the environment it was developed in (no root there);
# the compose lab is the verified path.
set -eu
LAB=$(cd "$(dirname "$0")/.." && pwd)
L="$LAB/local"
ROOTS="$L/roots"
RUN="$L/run"

[ "$(id -u)" = 0 ] || { echo "lab/local/up.sh must run as root" >&2; exit 1; }
for c in ip unshare nsenter sshd sudo socat useradd install; do
  command -v "$c" >/dev/null 2>&1 || { echo "missing: $c" >&2; exit 1; }
done
[ -x /usr/sbin/sshd ] || { echo "missing /usr/sbin/sshd" >&2; exit 1; }

# host -> "net:ip net:ip"
HOSTS="jump:a:172.30.1.5,b:172.30.2.5
a1:a:172.30.1.11
a2:a:172.30.1.12
a3:a:172.30.1.13
a4:a:172.30.1.14
a5:a:172.30.1.15
b1:b:172.30.2.11
b2:b:172.30.2.12
b3:b:172.30.2.13,c:172.30.3.13
b4:b:172.30.2.14
b5:b:172.30.2.15
c1:c:172.30.3.21
c2:c:172.30.3.22"

mkdir -p "$ROOTS" "$RUN" /lab
chmod 700 "$RUN"

# ---- bridges (the root namespace gets .1 so that the test harness can reach the lab-control sshd)
for n in a b c; do
  case $n in a) net=172.30.1;; b) net=172.30.2;; c) net=172.30.3;; esac
  ip link show "sbbr-$n" >/dev/null 2>&1 || ip link add "sbbr-$n" type bridge
  ip addr replace "$net.1/24" dev "sbbr-$n"
  ip link set "sbbr-$n" up
done

# /etc/hosts for name resolution on the hosts (Docker DNS stands in for this in compose)
HOSTS_FILE="127.0.0.1 localhost
$(printf '%s\n' "$HOSTS" | awk -F: '{split($0, p, ":"); n = $1; sub(/^[^:]*:/, "", $0);
  m = split($0, nets, ","); for (i = 1; i <= m; i++) { split(nets[i], x, ":"); print x[2], n } }')"

printf '%s\n' "$HOSTS" | while IFS= read -r line; do
  h=${line%%:*}
  nets=${line#*:}
  R="$ROOTS/$h"
  if [ ! -f "$R/.built" ]; then
    rm -rf "$R"
    mkdir -p "$R/root" "$R/home" "$R/var-backups" "$R/lab"
    cp -a /etc "$R/etc"
    rm -f "$R/etc/ssh/ssh_host_"* "$R/etc/sudoers.d/"* 2>/dev/null || true
    printf '%s\n' "$HOSTS_FILE" > "$R/etc/hosts"
    printf '%s\n' "$h" > "$R/etc/hostname"
    chmod 700 "$R/root"
    cp -a /var/backups/. "$R/var-backups/" 2>/dev/null || true
    mkdir -p "$R/lab/image"
    cp -a "$LAB/keys" "$R/lab/keys"
    cp "$LAB/image/lib.sh" "$LAB/image/entrypoint.sh" "$LAB/image/ctl_sshd_config" "$R/lab/image/"
    cp -a "$LAB/seed/$h" "$R/lab/seed"
    # build: the same steps as the Dockerfile, inside a mount namespace that sees the host's own dirs
    unshare -m sh -c "
      mount --make-rprivate /
      mount --bind '$R/etc' /etc
      mount --bind '$R/root' /root
      mount --bind '$R/home' /home
      mount --bind '$R/var-backups' /var/backups
      mount --bind '$R/lab' /lab
      sh /lab/image/lib.sh common '$h' && sh /lab/seed/setup.sh && sh /lab/image/lib.sh finish '$h'
    "
    touch "$R/.built"
  fi

  ns="sb-$h"
  ip netns list | grep -qw "$ns" || ip netns add "$ns"
  ip -n "$ns" link set lo up
  i=0
  for m in $(printf '%s' "$nets" | tr ',' ' '); do
    n=${m%%:*}
    ipaddr=${m#*:}
    veth="sb${h}${i}"
    if ! ip link show "$veth" >/dev/null 2>&1; then
      ip link add "$veth" type veth peer name "eth$i" netns "$ns"
      ip link set "$veth" master "sbbr-$n" up
      ip -n "$ns" addr add "$ipaddr/24" dev "eth$i"
      ip -n "$ns" link set "eth$i" up
    fi
    i=$((i + 1))
  done

  if [ -f "$RUN/$h.pid" ] && kill -0 "$(cat "$RUN/$h.pid")" 2>/dev/null; then
    continue
  fi
  # the host: own mount, UTS and PID namespace inside its network namespace; sshd -D becomes PID 1
  ip netns exec "$ns" unshare -m -u -p --fork --mount-proc sh -c "
    mount --make-rprivate /
    mount --bind '$R/etc' /etc
    mount --bind '$R/root' /root
    mount --bind '$R/home' /home
    mount --bind '$R/var-backups' /var/backups
    mount --bind '$R/lab' /lab
    hostname '$h'
    exec sh /lab/image/entrypoint.sh
  " >"$RUN/$h.log" 2>&1 &
  echo $! > "$RUN/$h.pid"
done

# 127.0.0.1:2222 -> jump:22 (as compose publishes it)
if ! { [ -f "$RUN/socat.pid" ] && kill -0 "$(cat "$RUN/socat.pid")" 2>/dev/null; }; then
  socat TCP-LISTEN:2222,bind=127.0.0.1,reuseaddr,fork TCP:172.30.1.5:22 >"$RUN/socat.log" 2>&1 &
  echo $! > "$RUN/socat.pid"
fi
sleep 1
echo "local lab up: entry 127.0.0.1:2222 (lab/local/down.sh removes it)"
