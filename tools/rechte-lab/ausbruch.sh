#!/bin/sh
# Lab test (test only): break-out attempts with the stolen audit key against jump (entry) and a1 (via jump).
# Usage: tools/rechte-lab/ausbruch.sh  - prints each attempt, its command and the result.
cd "$(dirname "$0")/../.." || exit 1
PY=${PY:-/state/venv/bin/python}
A="$PY tools/rechte-lab/als_sshbite.py"
SUDO='test -x /usr/bin/sudo && exec /usr/bin/sudo'
n=0
t() {  # t TITLE TARGET COMMAND [STDIN]
  n=$((n + 1))
  case "$2" in
    --tcp*) set -- "$1" "$2" "$3" "${4:-}"; d=$(printf '%s' "$2" | awk '{print "-W " $2 " sshbite@" $3}') ;;
    --direct*) d="sshbite@$(printf '%s' "$2" | awk '{print $2}') (direkt vom Scanner)" ;;
    --pty*) d="-t sshbite@${2#--pty }" ;;
    *) d="sshbite@$2" ;;
  esac
  printf '\n### %02d %s\n$ ssh %s %s\n' "$n" "$1" "$d" "$3"
  [ -n "${4:-}" ] && printf '  (stdin: %s)\n' "$4"
  printf '%s' "${4:-}" | $A $2 "$3" 2>&1 | head -n 14
}
t "Interaktive Shell (mit PTY)" "--pty jump" "" "id
exit
"
t "Beliebiger Befehl ohne sudo" jump "id"
t "sudo -i" jump "sudo -i"
t "sudo sh" jump "sudo -n sh -c id"
t "sudo cat /etc/shadow" jump "sudo -n cat /etc/shadow"
t "sudo -l" jump "sudo -n -l"
t "Eigenes Skript per stdin an sudo /bin/sh -s (exakter SSHBITE-Befehl)" jump "$SUDO -n /bin/sh -s; exec /bin/sudo -n /bin/sh -s" "id; head -n 2 /etc/shadow"
t "Collector mit Argument" jump "sudo -n /usr/local/libexec/sshbite/sshbite-collect -x"
t "Collector direkt mit Umgebungsvariable" jump "LD_PRELOAD=/tmp/x.so sudo -n /usr/local/libexec/sshbite/sshbite-collect"
t "Collector direkt (ohne Gate-Pfad)" jump "sudo -n /usr/local/libexec/sshbite/sshbite-collect"
t "Gate-Befehl plus angehängter Befehl" jump "$SUDO -n /bin/sh -s; exec /bin/sudo -n /bin/sh -s; id" "x"
t "Passwort-Variante mit Skript" jump "$SUDO -S -k -p '' /bin/sh -s; exec /bin/sudo -S -k -p '' /bin/sh -s" "pw
id"
t "Unprivilegierte Shell /bin/sh -s" jump "/bin/sh -s" "id"
t "sudo-login-Variante -i" jump "$SUDO -n -i /bin/sh -s; exec /bin/sudo -n -i /bin/sh -s" "id"
t "Namensauflösung mit eingeschleustem Befehl" jump "/bin/sh -c 'id'"
t "Datei lesen ohne sudo" jump "cat /etc/passwd"
t "Weiterleitung von jump zu SSH-Port eines Hosts" "--tcp 172.30.1.11:22 jump" ""
t "Weiterleitung von jump zu anderem Port (2200)" "--tcp 172.30.1.11:2200 jump" ""
t "Weiterleitung über Zielhost a1 (kein Hop)" "--tcp 172.30.1.12:22 172.30.1.11" ""
t "Login auf a1 direkt vom Scanner statt über jump" "--direct 172.30.1.11 a1" "id"
t "Zielhost a1 über jump: sudo sh" 172.30.1.11 "sudo -n sh -c id"
t "Zielhost a1: Skript per stdin" 172.30.1.11 "$SUDO -n /bin/sh -s; exec /bin/sudo -n /bin/sh -s" "id"
