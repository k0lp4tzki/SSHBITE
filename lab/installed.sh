#!/bin/sh
# Lab only: put a lab host into privilege.mode installed (docs/install.md, "Privileges: installed collector")
# and back. Runs as root inside a lab host through the lab-control sshd (tests/e2e/lab.py LabControl).
#
#   installed.sh apply DIR 'AUTHORIZED_KEYS_LINE'
#       DIR holds the files of `sshbite collector export` (the test writes them as heredocs into a
#       generated script, LabControl.run_text). Checks SHA256SUMS, backs up the original state once to
#       /lab/installed-orig/, removes every other sudoers rule for sshbite, installs the files exactly as
#       docs/install.md says and checks that `sudo -l -U sshbite` lists only the collector.
#   installed.sh remove
#       restores the backed-up state: sudoers.d files, ~sshbite/.ssh/authorized_keys, owners, modes and
#       /etc/shadow (passwd -l), the directory mtimes, so that lab/snapshot.sh shows the host exactly as before `apply`.
#
# Nothing here is part of SSHBITE: it is the owner's installation step, done by the test in the lab.
set -eu
LC_ALL=C; export LC_ALL
BAK=/lab/installed-orig
LIBEXEC=/usr/local/libexec/sshbite
H=/home/sshbite
DIRS="/etc /etc/sudoers.d $H $H/.ssh"

backup() {
  [ -f "$BAK/complete" ] && return 0      # apply again (after a test broke a host): keep the first backup
  rm -rf "$BAK"
  mkdir -p "$BAK/sudoers.d"
  for f in /etc/sudoers.d/*; do
    if [ -e "$f" ]; then cp -p "$f" "$BAK/sudoers.d/"; fi
  done
  cp -p "$H/.ssh/authorized_keys" "$BAK/authorized_keys"
  cp -p /etc/shadow "$BAK/shadow"                # passwd -l rewrites it where the account was not locked
  if [ -e /etc/shadow- ]; then cp -p /etc/shadow- "$BAK/shadow-"; fi
  i=0
  for d in $DIRS; do
    i=$((i + 1))
    touch -r "$d" "$BAK/mtime.$i"         # reference file: keeps the mtime to the nanosecond
    stat -c "%n %u %g %a $i" "$d"
  done > "$BAK/dirs"
  [ -d /usr/local/libexec ] || : > "$BAK/no-libexec"
  : > "$BAK/complete"
}

case "${1:-}" in
apply)
  D=$2
  LINE=$3
  ( cd "$D" && sha256sum -c --quiet SHA256SUMS )
  backup
  # every other sudoers rule for the audit account goes (e.g. NOPASSWD: ALL, /bin/sh -s)
  for f in /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    if grep -Eq '^[[:space:]]*(sshbite[[:space:]]|Defaults:sshbite)' "$f"; then rm -f "$f"; fi
  done
  # --- the steps of docs/install.md ---
  id sshbite >/dev/null || useradd -m -s /bin/sh sshbite
  passwd -S sshbite | grep -q ' L ' || passwd -l sshbite      # the lab account is locked already
  install -d -m 0755 -o root -g root "$LIBEXEC"
  install -m 0755 -o root -g root "$D/sshbite-collect" "$D/sshbite-resolve" "$D/sshbite-gate" "$LIBEXEC/"
  install -m 0440 -o root -g root "$D/sudoers.d-sshbite" /etc/sudoers.d/sshbite && visudo -cf /etc/sudoers.d/sshbite
  chown root:root "$H" && chmod 0755 "$H"
  install -d -m 0755 -o root -g root "$H/.ssh"
  printf '%s\n' "$LINE" > "$D/authorized_keys.sshbite.edited"
  install -m 0644 -o root -g root "$D/authorized_keys.sshbite.edited" "$H/.ssh/authorized_keys"
  # --- checks ---
  rules=$(sudo -l -U sshbite | sed -n '/may run the following commands/,$p' | sed 1d | sed '/^[[:space:]]*$/d')
  want="    (root) NOPASSWD: $LIBEXEC/sshbite-collect \"\""
  if [ "$rules" != "$want" ]; then
    printf 'sudo -l -U sshbite lists more than the collector:\n%s\n' "$rules" >&2
    exit 1
  fi
  stat -c '%U %a %n' /usr /usr/local /usr/local/libexec "$LIBEXEC" "$LIBEXEC"/*
  rm -rf "$D"
  ;;
remove)
  [ -f "$BAK/complete" ] || { echo "nothing to remove: no backup in $BAK"; exit 0; }
  rm -rf "$LIBEXEC"
  if [ -f "$BAK/no-libexec" ]; then rmdir /usr/local/libexec 2>/dev/null || :; fi
  rm -f /etc/sudoers.d/*
  for f in "$BAK"/sudoers.d/*; do
    if [ -e "$f" ]; then cp -p "$f" /etc/sudoers.d/; fi
  done
  cp -p "$BAK/authorized_keys" "$H/.ssh/authorized_keys"
  if ! cmp -s "$BAK/shadow" /etc/shadow; then cp -p "$BAK/shadow" /etc/shadow; fi
  if [ -e "$BAK/shadow-" ]; then
    if ! cmp -s "$BAK/shadow-" /etc/shadow-; then cp -p "$BAK/shadow-" /etc/shadow-; fi
  else
    rm -f /etc/shadow-
  fi
  while read -r d uid gid mode i; do
    chown "$uid:$gid" "$d"
    chmod "$mode" "$d"
    touch -m -r "$BAK/mtime.$i" "$d"
  done < "$BAK/dirs"
  rm -rf "$BAK"
  echo "restored"
  ;;
*)
  echo "usage: installed.sh apply DIR LINE | remove" >&2
  exit 2
  ;;
esac
