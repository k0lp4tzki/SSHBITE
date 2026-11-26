#!/bin/sh
# Check that the collector's sshd/ssh-keygen calls write nothing anywhere (spec 3.6; owner's hard requirement).
# Lists the whole root filesystem (mtime, ctime, size) except pseudo filesystems and log/run dirs, runs the
# exact commands of collect.sh, lists again and prints every difference. Runs as root in one session, so
# login records of the session itself are not in between. Usage: sh -s KEYFILE < lab/writecheck.sh
LC_ALL=C; export LC_ALL
k=$1
list() {
  find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/log \) -prune -o \
       -printf '%p %m %U %G %s %T@ %C@\n' 2>/dev/null | sort
}
before=$(list)
/usr/sbin/sshd -T >/dev/null 2>&1
ssh-keygen -y -P '' -f "$k" </dev/null >/dev/null 2>&1
ssh-keygen -l -f "$k" </dev/null >/dev/null 2>&1
after=$(list)
if [ "$before" = "$after" ]; then
  echo "NO CHANGES ($(printf '%s\n' "$before" | wc -l) paths compared)"
else
  echo "CHANGED:"
  { printf '%s\n' "$before" | sed 's/^/B /'; printf '%s\n' "$after" | sed 's/^/A /'; } |
    awk '{k = substr($0, 3); if ($1 == "B") b[k] = 1; else a[k] = 1}
         END {for (k in b) if (!(k in a)) print "- " k; for (k in a) if (!(k in b)) print "+ " k}'
fi
