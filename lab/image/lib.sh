#!/bin/sh
# Build-time helpers for the lab image. Usage from seed/<host>/setup.sh:  . /lab/image/lib.sh
set -eu
K=/lab/keys
F=/lab/seed/files

# mkuser NAME [SHELL]
mkuser() {
  id "$1" >/dev/null 2>&1 || useradd -m -s "${2:-/bin/bash}" "$1"
}

# sshdir USER - ~/.ssh with 0700, owned by the user
sshdir() {
  h=$(getent passwd "$1" | cut -d: -f6)
  install -d -m 700 -o "$1" -g "$(id -gn "$1")" "$h/.ssh"
}

# put PATH OWNER MODE - install the rendered seed file at its target path
put() {
  install -D -m "$3" -o "$2" -g "$(id -gn "$2")" "$F$1" "$1"
}

# privkey KEYNAME DEST OWNER MODE [with-pub]
privkey() {
  install -D -m "$4" -o "$3" -g "$(id -gn "$3")" "$K/$1" "$2"
  if [ "${5:-}" = with-pub ]; then
    install -m 644 -o "$3" -g "$(id -gn "$3")" "$K/$1.pub" "$2.pub"
  fi
}

# sshd_lab PERMITROOTLOGIN PASSWORDAUTH
sshd_lab() {
  printf 'PermitRootLogin %s\nPasswordAuthentication %s\n' "$1" "$2" > /etc/ssh/sshd_config.d/lab.conf
}

common() {
  host=$1
  install -m 600 "$K/${host}_host_ed25519" /etc/ssh/ssh_host_ed25519_key
  install -m 644 "$K/${host}_host_ed25519.pub" /etc/ssh/ssh_host_ed25519_key.pub
  install -m 600 "$K/${host}_host_ecdsa" /etc/ssh/ssh_host_ecdsa_key
  install -m 644 "$K/${host}_host_ecdsa.pub" /etc/ssh/ssh_host_ecdsa_key.pub
  sshd_lab prohibit-password no
  # the audit account
  useradd -m -s /bin/sh sshbite
  sshdir sshbite
  install -m 600 -o sshbite -g sshbite "$K/audit_ed25519.pub" /home/sshbite/.ssh/authorized_keys
  printf 'sshbite ALL=(root) NOPASSWD: ALL\n' > /etc/sudoers.d/sshbite
  chmod 440 /etc/sudoers.d/sshbite
  # lab control (test harness only, outside /etc, /root, /home)
  install -d -m 700 /lab/ctl
  install -m 600 "$K/labctl_host_ed25519" /lab/ctl/host_ed25519
  install -m 600 "$K/labctl_ed25519.pub" /lab/ctl/authorized_keys
  mv /lab/image/ctl_sshd_config /lab/ctl/sshd_config
}

finish() {
  host=$1
  # keep originals of everything the e2e test changes, for lab reset
  mkdir -p /lab/orig
  for f in /root/.ssh/authorized_keys /home/www/.ssh/authorized_keys /etc/ssh/ssh_host_ed25519_key \
           /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key /etc/ssh/ssh_host_ecdsa_key.pub; do
    if [ -f "$f" ]; then
      mkdir -p "/lab/orig$(dirname "$f")"
      cp -p "$f" "/lab/orig$f"
    fi
  done
  # only c2 keeps its rotated host keys; other hosts drop the key directory
  if [ "$host" = c2 ]; then
    mkdir -p /lab/rotated
    cp "$K"/c2_rotated_host_* /lab/rotated/
  fi
  if [ "$host" = b2 ]; then
    cp /lab/seed/k_new.line /lab/k_new.line
  fi
  rm -rf "$K" /lab/seed
  sshd -t
}

if [ "${1:-}" = common ]; then common "$2"; fi
if [ "${1:-}" = finish ]; then finish "$2"; fi
