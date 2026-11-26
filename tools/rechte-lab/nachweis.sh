#!/bin/sh
# Reproduces chapter 7 of deliverables/SSHBITE-Minimale-Rechte.md against the running lab
# (compose.yaml / compose.lab.yaml): today's install.md rule, then the minimal configuration.
# Needs: a venv with SSHBITE installed (PY, SB), the lab reachable as jump, a1, ... (ports 22 and 2200).
set -u
cd "$(dirname "$0")/../.." || exit 1
PY=${PY:-/state/venv/bin/python}
SB=${SB:-/state/venv/bin/sshbite}
T=tools/rechte-lab
O=deliverables/nachweis
LAB=${LAB:-/state/lab}
export SSHBITE_CONFIG=$LAB/sshbite.yaml
mkdir -p "$O" "$LAB"
rm -f "$LAB/sshbite.db"
sed -e "s#^database:.*#database: $LAB/sshbite.db#" -e 's#host: 172.30.1.5#host: jump#' \
    -e "s#key_file:.*#key_file: $PWD/lab/keys/audit_ed25519#" lab/demo/sshbite.yaml > "$SSHBITE_CONFIG"
chmod 600 "$SSHBITE_CONFIG" lab/keys/audit_ed25519 lab/keys/labctl_ed25519
run() { printf '\n$ %s\n' "$*"; "$@" 2>&1; }

{ echo "# A. Heutiger Stand: sudoers-Zeile aus docs/install.md auf allen Lab-Hosts ($(date -u +%FT%TZ))"
  run "$PY" $T/lab_apply.py installmd
  run "$SB" config validate --connect
  run "$SB" scan --label "install.md-Regel"
  run "$PY" $T/scan_hosts.py "$LAB/sshbite.db" 1
  printf '\n$ sshbite-pruefen.sh auf jump\n'; "$PY" $T/labctl.py jump 'sh -s' < deliverables/config/sshbite-pruefen.sh; echo "Exit $?"
} > $O/01-heute-scan.txt
$T/ausbruch.sh > $O/02-heute-ausbruch.txt 2>&1

{ echo "# B. Minimal-Konfiguration aus deliverables/config/ auf allen Lab-Hosts ($(date -u +%FT%TZ))"
  run "$PY" $T/lab_apply.py minimal
  printf '\n$ sshbite-pruefen.sh auf jump\n'; "$PY" $T/labctl.py jump 'sh -s' < deliverables/config/sshbite-pruefen.sh; echo "Exit $?"
  run "$SB" config validate --connect
  run "$SB" scan --label "minimal"
  run "$PY" $T/scan_hosts.py "$LAB/sshbite.db" 2
  run "$SB" diff 1 2
} > $O/03-minimal-scan.txt
$T/ausbruch.sh > $O/04-minimal-ausbruch.txt 2>&1
"$PY" $T/labctl.py jump 'sh -s' < $T/lokal.sh > $O/05-minimal-lokale-shell.txt 2>&1

{ echo "# C. Collector-Version passt nicht (a5: eine Zeile an die installierte Kopie angehaengt)"
  "$PY" $T/labctl.py a5 'printf "# lokal geaendert\n" >> /usr/local/libexec/sshbite/sshbite-collect' </dev/null
  run "$SB" scan --label "a5 falsche Version"
  "$PY" $T/scan_hosts.py "$LAB/sshbite.db" 3 | grep -E '^(Host|a5) '
  "$PY" $T/labctl.py a5 'sed -i "\$d" /usr/local/libexec/sshbite/sshbite-collect' </dev/null
  echo
  echo "# D. Symlink-Race eines lokalen Benutzers (ops auf jump) gegen den Collector (200 Laeufe als root)"
  "$PY" $T/labctl.py jump 'N=200 sh -s' < $T/toctou.sh 2>&1 | grep -v '^Session terminated'
} > $O/06-version-und-race.txt 2>&1
echo "Nachweis geschrieben nach $O/"
