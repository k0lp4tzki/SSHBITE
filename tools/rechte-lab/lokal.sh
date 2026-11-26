#!/bin/sh
# Lab test (test only, runs as root on a lab host via labctl.py): what the sudoers rule alone allows if an
# attacker had a shell as sshbite anyway (second line of defence behind the forced command).
C=/usr/local/libexec/sshbite/sshbite-collect
t() {  # t TITLE COMMAND
  printf '\n### %s\nsshbite$ %s\n' "$1" "$2"
  out=$(su -s /bin/sh sshbite -c "$2" </dev/null 2>&1)
  rc=$?
  printf '%s\n' "$out" | head -n 6
  printf '[exit %s]\n' "$rc"
}
t "sudo -l" "sudo -n -l"
t "sudo -i" "sudo -n -i"
t "sudo sh" "sudo -n /bin/sh -c id"
t "sudo cat /etc/shadow" "sudo -n /usr/bin/cat /etc/shadow"
t "sudo /bin/true (heute Probe von SSHBITE)" "sudo -n /bin/true"
t "Collector mit Argument" "sudo -n $C /etc/shadow"
t "Collector mit Umgebungsvariable LD_PRELOAD" "LD_PRELOAD=/tmp/x.so sudo -n $C | head -n 1"
t "Umgebungsvariable per sudo VAR=wert" "sudo -n PATH=/tmp $C"
t "Umgebung behalten (-E)" "sudo -n -E $C"
t "Anderes Ziel-Konto (-u)" "sudo -n -u daemon $C"
t "Collector ueberschreiben" "printf 'id' > $C"
t "Eigene Datei ins Verzeichnis legen" "touch /usr/local/libexec/sshbite/x"
t "Im eigenen Home schreiben" "touch /home/sshbite/.ssh/known_hosts"
t "authorized_keys aendern" "printf x >> /home/sshbite/.ssh/authorized_keys"
t "Collector ausfuehren (erlaubt): erste Zeilen" "sudo -n $C | head -n 3"
t "Collector-Ausgabe: Zeilen mit privatem Schluesselmaterial?" "sudo -n $C | grep -c -e '^|-----BEGIN' -e '^|b3BlbnNzaC1rZXktdjE' -e '^|MII'"
t "Collector-Ausgabe: shadow-Abschnitt (nur 1. Zeichen des Hashes)" "sudo -n $C | sed -n '/^#S SHADOW/,/^#S USERS/p' | head -n 4"
