#!/bin/sh
# Lab changes made by the e2e test between scans (spec 9.3), outside the read-only brackets.
# Run as root inside a lab host: sh -s <action> < lab/labctl.sh
#   scan2-a5   delete the K_FLEET line from /root/.ssh/authorized_keys
#   scan2-b2   append K_NEW to /home/www/.ssh/authorized_keys
#   scan2-c2   install the rotated host keys and restart sshd
#   reset      restore the original state of all of the above
set -eu
restart_sshd() {
  kill -HUP 1
  sleep 1
  i=0
  while [ $i -lt 50 ]; do
    if ss -ltn 2>/dev/null | grep -q ':22 ' ; then break; fi
    sleep 0.1; i=$((i + 1))
  done
  sleep 0.5
}
case "$1" in
  scan2-a5)
    sed -i '/fleet-deploy/d' /root/.ssh/authorized_keys ;;
  scan2-b2)
    cat /lab/k_new.line >> /home/www/.ssh/authorized_keys ;;
  scan2-c2)
    for t in ed25519 ecdsa; do
      install -m 600 "/lab/rotated/c2_rotated_host_$t" "/etc/ssh/ssh_host_${t}_key"
      install -m 644 "/lab/rotated/c2_rotated_host_$t.pub" "/etc/ssh/ssh_host_${t}_key.pub"
    done
    restart_sshd ;;
  reset)
    changed=0
    for f in /root/.ssh/authorized_keys /home/www/.ssh/authorized_keys; do
      if [ -f "/lab/orig$f" ] && ! cmp -s "/lab/orig$f" "$f"; then cp -p "/lab/orig$f" "$f"; fi
    done
    for f in /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key \
             /etc/ssh/ssh_host_ecdsa_key.pub; do
      if [ -f "/lab/orig$f" ] && ! cmp -s "/lab/orig$f" "$f"; then cp -p "/lab/orig$f" "$f"; changed=1; fi
    done
    if [ $changed = 1 ]; then restart_sshd; fi ;;
  *) echo "unknown action $1" >&2; exit 2 ;;
esac
