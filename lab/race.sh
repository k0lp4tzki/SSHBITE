#!/bin/sh
# Lab only: the symlink race of the review (spec 8.2/8.3, test i08). Runs as root inside a lab host through the
# lab-control sshd (tests/e2e/lab.py LabControl.run):  sh -s start|stop|count N < lab/race.sh
#
#   start   creates the local user racer with ~/.ssh, two root-only canaries
#             /root/race-canary              (0600, "RACE-CANARY-<16 hex>")
#             /root/race-dir/known_hosts     (directory 0700, the same line)
#           and starts two endless loops as racer (setpriv):
#             (a) ~/.ssh/known_hosts flips between a regular file and a symlink to /root/race-canary
#             (b) ~/.ssh itself flips between the directory and a symlink to /root/race-dir
#           every flip is a rename (mv -T), so each name is always either the one or the other.
#   count N the control: N x `head -n 5 ~racer/.ssh/known_hosts` as root; prints how many saw the canary.
#           A reader with root's rights follows the links - this is what the collector must never do.
#   stop    ends the loops, removes racer (userdel -r) and the canaries, and puts /etc/passwd, shadow, group
#           (and their backups, gshadow, subuid, subgid) and the mtimes of /etc, /home and /root back as they
#           were before start, so that lab/snapshot.sh shows the host as before.
set -eu
LC_ALL=C; export LC_ALL
R=/lab/race                       # outside /etc, /root, /home: not part of the read-only snapshot
FILES="passwd passwd- shadow shadow- group group- gshadow gshadow- subuid subuid- subgid subgid- .pwd.lock"
DIRS="/etc /home /root"

start() {
  [ ! -e "$R" ] || { echo "race already started ($R exists)" >&2; exit 1; }
  mkdir -p "$R/etc"
  for f in $FILES; do
    if [ -e "/etc/$f" ]; then cp -p "/etc/$f" "$R/etc/$f"; else : > "$R/etc/$f.absent"; fi
  done
  i=0
  for d in $DIRS; do
    i=$((i + 1))
    touch -r "$d" "$R/mtime.$i"
  done
  canary="RACE-CANARY-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
  printf '%s\n' "$canary" > "$R/canary"
  useradd -m -s /bin/sh racer
  H=$(getent passwd racer | cut -d: -f6)
  install -d -m 700 -o racer -g racer "$H/.ssh"
  ( umask 077; printf '%s\n' "$canary" > /root/race-canary )
  install -d -m 700 /root/race-dir
  ( umask 077; printf '%s\n' "$canary" > /root/race-dir/known_hosts )
  # the racer's loops: (a) the file, (b) the directory. Errors are expected (while ~/.ssh is the link to
  # /root/race-dir, racer cannot write there) and ignored.
  cat > "$R/loop-a" <<'LOOP'
cd "$HOME" || exit 1
while :; do
  printf 'racer.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6jZpFBdpQjQ6yJ8bTt5jW4m5dQ1lDzW3gVq1r2s3t4\n' > .ssh/kh.file
  mv -T .ssh/kh.file .ssh/known_hosts
  ln -s /root/race-canary .ssh/kh.link
  mv -T .ssh/kh.link .ssh/known_hosts
done
LOOP
  cat > "$R/loop-b" <<'LOOP'
cd "$HOME" || exit 1
while :; do
  ln -s /root/race-dir ssh.link
  mv -T .ssh ssh.dir && mv -T ssh.link .ssh
  mv -T .ssh ssh.link && mv -T ssh.dir .ssh
  rm -f ssh.link
done
LOOP
  chmod 644 "$R/loop-a" "$R/loop-b"
  chmod 755 "$R"
  for l in a b; do
    setpriv --reuid=racer --regid=racer --init-groups --no-new-privs env HOME="$H" sh "$R/loop-$l" \
      </dev/null >/dev/null 2>&1 &
    echo $! >> "$R/pids"
  done
  sleep 1
  echo "race started: racer, canary $(cut -c1-12 "$R/canary")..., loops $(tr '\n' ' ' < "$R/pids")"
}

count() {
  n=${1:-200}
  H=$(getent passwd racer | cut -d: -f6)
  hits=0
  i=0
  while [ "$i" -lt "$n" ]; do
    i=$((i + 1))
    if head -n 5 "$H/.ssh/known_hosts" 2>/dev/null | grep -q RACE-CANARY; then hits=$((hits + 1)); fi
  done
  echo "control $hits/$n"
}

stop() {
  [ -d "$R" ] || { echo "race not started"; exit 0; }
  # the loops first, then whatever they had started (the Debian image has no procps: /proc)
  if [ -f "$R/pids" ]; then
    for p in $(cat "$R/pids"); do kill -KILL "$p" 2>/dev/null || :; done
  fi
  ruid=$(id -u racer 2>/dev/null || echo none)
  i=0
  while [ "$i" -lt 50 ]; do
    left=0
    for d in /proc/[0-9]*; do
      if [ "$(stat -c %u "$d" 2>/dev/null)" = "$ruid" ]; then
        kill -KILL "${d#/proc/}" 2>/dev/null || :
        left=1
      fi
    done
    [ "$left" = 1 ] || break
    sleep 0.1
    i=$((i + 1))
  done
  H=$(getent passwd racer | cut -d: -f6 || :)
  userdel -r racer 2>/dev/null || userdel racer
  if [ -n "$H" ]; then rm -rf "$H"; fi
  rm -rf /root/race-canary /root/race-dir /var/mail/racer /var/spool/mail/racer
  for f in $FILES; do
    if [ -e "$R/etc/$f.absent" ]; then
      rm -f "/etc/$f"
    elif ! cmp -s "$R/etc/$f" "/etc/$f"; then
      cp -p "$R/etc/$f" "/etc/$f"
    else
      touch -r "$R/etc/$f" "/etc/$f"
    fi
  done
  i=0
  for d in $DIRS; do
    i=$((i + 1))
    touch -m -r "$R/mtime.$i" "$d"
  done
  rm -rf "$R"
  echo "race stopped"
}

case "${1:-}" in
  start) start ;;
  count) count "${2:-200}" ;;
  stop) stop ;;
  *) echo "usage: race.sh start|count N|stop" >&2; exit 2 ;;
esac
