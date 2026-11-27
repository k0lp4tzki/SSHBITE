#!/bin/sh
# Lab only: the symlink race of the review (spec 8.2/8.3, test i08), the FIFO race and the output flood of check-4
# (test i09). Runs as root inside a lab host through the lab-control sshd (tests/e2e/lab.py LabControl.run):
#   sh -s start [symlink|fifo|flood] | count N | procs | stop  < lab/race.sh
#
#   start [symlink]   creates the local user racer with ~/.ssh, two root-only canaries
#             /root/race-canary              (0600, "RACE-CANARY-<16 hex>")
#             /root/race-dir/known_hosts     (directory 0700, the same line)
#           and starts two endless loops as racer (setpriv):
#             (a) ~/.ssh/known_hosts flips between a regular file and a symlink to /root/race-canary
#             (b) ~/.ssh itself flips between the directory and a symlink to /root/race-dir
#           every flip is a rename (mv -T), so each name is always either the one or the other.
#   start fifo        the same user and canary; one loop flips ~/.ssh/known_hosts between a regular file, the
#           symlink to /root/race-canary and a FIFO that nobody writes (opening it for reading blocks for ever).
#   start flood       racer gets 40 files ~/.ssh/fNN.pub of 1,000,000 bytes (5000 lines) - 40 MB, more than the
#           transport's 32 MiB; then the user zvictim (later in /etc/passwd) with one authorized key, comment
#           VICTIMBACKDOOR. No loop.
#   count N the control: N x `head -n 5 ~racer/.ssh/known_hosts` as root; prints how many saw the canary
#           ("control H/N"); in mode fifo each read gets 2 s (timeout) and the hangs are counted too
#           ("control H/N hung M/N"). A reader with root's rights follows the links and blocks on the FIFO -
#           this is what the collector must never do.
#   procs   prints every process of root whose command line names sudo or sshbite-collect (from /proc: the
#           Debian image has no procps), one per line, nothing if there is none.
#   stop    ends the loops, removes racer and zvictim (userdel -r) and the canaries, and puts /etc/passwd, shadow, group
#           (and their backups, gshadow, subuid, subgid) and the mtimes of /etc, /home and /root back as they
#           were before start, so that lab/snapshot.sh shows the host as before.
set -eu
LC_ALL=C; export LC_ALL
R=/lab/race                       # outside /etc, /root, /home: not part of the read-only snapshot
FILES="passwd passwd- shadow shadow- group group- gshadow gshadow- subuid subuid- subgid subgid- .pwd.lock"
DIRS="/etc /home /root"

start() {
  mode=${1:-symlink}
  case "$mode" in symlink | fifo | flood) ;; *) echo "unknown mode $mode" >&2; exit 2 ;; esac
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
  printf '%s\n' "$mode" > "$R/mode"
  if [ "$mode" = flood ]; then
    awk 'BEGIN { s = "ssh-ed25519 "; for (i = 0; i < 186; i++) s = s "A"; for (i = 0; i < 5000; i++) print s " flood" }' \
      > "$H/.ssh/f00.pub"
    i=1
    while [ "$i" -lt 40 ]; do
      cp "$H/.ssh/f00.pub" "$H/.ssh/f$(printf %02d "$i").pub"
      i=$((i + 1))
    done
    chown -R racer:racer "$H/.ssh"
    useradd -m -s /bin/sh zvictim
    V=$(getent passwd zvictim | cut -d: -f6)
    install -d -m 700 -o zvictim -g zvictim "$V/.ssh"
    ssh-keygen -q -t ed25519 -N '' -C VICTIMBACKDOOR -f "$R/victim" >/dev/null
    install -m 600 -o zvictim -g zvictim "$R/victim.pub" "$V/.ssh/authorized_keys"
    chmod 755 "$R"
    echo "flood started: racer with $(ls "$H/.ssh" | wc -l) files, $(du -sk "$H/.ssh" | cut -f1) KiB; zvictim $(cut -d' ' -f2 "$R/victim.pub" | cut -c1-24)..."
    return 0
  fi
  ( umask 077; printf '%s\n' "$canary" > /root/race-canary )
  install -d -m 700 /root/race-dir
  ( umask 077; printf '%s\n' "$canary" > /root/race-dir/known_hosts )
  # the racer's loops: (a) the file, (b) the directory. Errors are expected (while ~/.ssh is the link to
  # /root/race-dir, racer cannot write there) and ignored.
  if [ "$mode" = fifo ]; then
    cat > "$R/loop-a" <<'LOOP'
cd "$HOME" || exit 1
while :; do
  printf 'racer.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6jZpFBdpQjQ6yJ8bTt5jW4m5dQ1lDzW3gVq1r2s3t4\n' > .ssh/kh.file
  mv -T .ssh/kh.file .ssh/known_hosts
  ln -s /root/race-canary .ssh/kh.link
  mv -T .ssh/kh.link .ssh/known_hosts
  mkfifo .ssh/kh.fifo
  mv -T .ssh/kh.fifo .ssh/known_hosts
done
LOOP
    loops=a
  else
    loops="a b"
  fi
  [ "$mode" = fifo ] || cat > "$R/loop-a" <<'LOOP'
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
  chmod 644 "$R"/loop-*
  chmod 755 "$R"
  for l in $loops; do
    setpriv --reuid=racer --regid=racer --init-groups --no-new-privs env HOME="$H" sh "$R/loop-$l" \
      </dev/null >/dev/null 2>&1 &
    echo $! >> "$R/pids"
  done
  sleep 1
  echo "race started ($mode): racer, canary $(cut -c1-12 "$R/canary")..., loops $(tr '\n' ' ' < "$R/pids")"
}

count() {
  n=${1:-200}
  H=$(getent passwd racer | cut -d: -f6)
  hits=0
  hung=0
  i=0
  if [ "$(cat "$R/mode" 2>/dev/null)" = fifo ]; then
    while [ "$i" -lt "$n" ]; do
      i=$((i + 1))
      r=0
      o=$(timeout -k 1 2 head -n 5 "$H/.ssh/known_hosts" 2>/dev/null) || r=$?
      if [ "$r" = 124 ] || [ "$r" = 137 ]; then hung=$((hung + 1)); fi
      case "$o" in *RACE-CANARY*) hits=$((hits + 1)) ;; esac
    done
    echo "control $hits/$n hung $hung/$n"
    return 0
  fi
  while [ "$i" -lt "$n" ]; do
    i=$((i + 1))
    if head -n 5 "$H/.ssh/known_hosts" 2>/dev/null | grep -q RACE-CANARY; then hits=$((hits + 1)); fi
  done
  echo "control $hits/$n"
}

procs() {
  for d in /proc/[0-9]*; do
    [ "$(stat -c %u "$d" 2>/dev/null)" = 0 ] || continue
    c=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null) || continue
    case "$c" in
      *sshbite-collect* | sudo\ * | */sudo\ *) echo "${d#/proc/} $c" ;;
    esac
  done
}

stop() {
  [ -d "$R" ] || { echo "race not started"; exit 0; }
  # the loops first, then whatever they had started (the Debian image has no procps: /proc)
  if [ -f "$R/pids" ]; then
    for p in $(cat "$R/pids"); do kill -KILL "$p" 2>/dev/null || :; done
  fi
  for u in racer zvictim; do
    ruid=$(id -u "$u" 2>/dev/null) || continue
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
    H=$(getent passwd "$u" | cut -d: -f6 || :)
    userdel -r "$u" 2>/dev/null || userdel "$u"
    if [ -n "$H" ]; then rm -rf "$H"; fi
    rm -rf "/var/mail/$u" "/var/spool/mail/$u"
  done
  rm -rf /root/race-canary /root/race-dir
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
  start) start "${2:-symlink}" ;;
  count) count "${2:-200}" ;;
  procs) procs ;;
  stop) stop ;;
  *) echo "usage: race.sh start [symlink|fifo|flood]|count N|procs|stop" >&2; exit 2 ;;
esac
