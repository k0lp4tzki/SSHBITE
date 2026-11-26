#!/bin/sh
# sshbite-pruefen.sh - prueft auf EINEM Host, ob die Minimal-Konfiguration fuer den SSHBITE-Audit-Account
# richtig liegt. Als root ausfuehren:  sh sshbite-pruefen.sh   (aendert nichts; Exit 0 = alles OK)
PATH=/usr/sbin:/usr/bin:/sbin:/bin
U=sshbite
D=/usr/local/libexec/sshbite
C=$D/sshbite-collect
G=$D/sshbite-gate
S=/etc/sudoers.d/sshbite
WANT_SHA=6c262392665b6cd321c7ac52834a69c1e1fcf2fe171552b863742c4ec9940f05   # collect.sh von SSHBITE 0.1.0
bad=0
ok()   { printf 'OK      %s\n' "$1"; }
fail() { printf 'FEHLER  %s\n' "$1"; bad=1; }

[ "$(id -u)" = 0 ] || { echo "als root ausfuehren"; exit 2; }
H=$(getent passwd "$U" | cut -d: -f6); SH=$(getent passwd "$U" | cut -d: -f7)
[ -n "$H" ] && ok "Account $U existiert (Home $H, Shell $SH)" || { fail "Account $U fehlt"; exit 1; }
case "$SH" in */nologin | */false) fail "Shell $SH: der Forced Command braucht /bin/sh" ;; *) ok "Shell $SH" ;; esac
id -nG "$U" | grep -qw -e sudo -e wheel -e adm -e shadow && fail "$U ist in einer privilegierten Gruppe: $(id -nG "$U")" || ok "keine privilegierten Gruppen ($(id -nG "$U"))"
passwd -S "$U" 2>/dev/null | awk '{print $2}' | grep -q '^L' && ok "Passwort gesperrt" || fail "Passwort nicht gesperrt (passwd -l $U)"

for p in "$D" "$C" "$G" "$S" "$H" "$H/.ssh" "$H/.ssh/authorized_keys"; do
  st=$(stat -c '%U %a' "$p" 2>/dev/null) || { fail "$p fehlt"; continue; }
  own=${st% *}; mode=${st#* }
  w=$(( (0$mode & 022) ))
  if [ "$own" = root ] && [ "$w" = 0 ]; then ok "$p root-eigen, Modus $mode"; else fail "$p: Eigentuemer $own, Modus $mode (root, nicht gruppen-/weltbeschreibbar)"; fi
done
[ "$(stat -c %a "$S" 2>/dev/null)" = 440 ] || fail "$S sollte Modus 0440 haben"
visudo -cf "$S" >/dev/null 2>&1 && ok "visudo -cf $S" || fail "visudo -cf $S meldet Fehler"
visudo -c >/dev/null 2>&1 && ok "visudo -c (gesamte sudo-Konfiguration)" || fail "visudo -c meldet Fehler"

L=$(sudo -l -U "$U" 2>/dev/null | sed -n '/may run the following/,$p' | tail -n +2 | sed 's/^ *//')
if [ "$L" = "(root) NOPASSWD: $C \"\"" ]; then ok "sudo -l -U $U: genau eine Regel: $L"
else fail "sudo -l -U $U zeigt mehr oder anderes als die eine Regel:"; printf '        %s\n' "$L"; fi

have=$(tail -n +2 "$C" 2>/dev/null | sha256sum | cut -d' ' -f1)
[ "$have" = "$WANT_SHA" ] && ok "Collector entspricht SSHBITE 0.1.0 (sha256 $have)" || fail "Collector-Pruefsumme $have, erwartet $WANT_SHA"

AK=$H/.ssh/authorized_keys
n=$(grep -cv -e '^#' -e '^[[:space:]]*$' "$AK" 2>/dev/null)
[ "$n" = 1 ] && ok "authorized_keys: genau ein Schluessel" || fail "authorized_keys: $n Schluesselzeilen (erwartet 1)"
k=$(grep -v -e '^#' -e '^[[:space:]]*$' "$AK" 2>/dev/null | head -n 1)
case "$k" in restrict,*) ok "authorized_keys: restrict" ;; *) fail "authorized_keys: Zeile beginnt nicht mit restrict" ;; esac
case "$k" in *"command=\"$G\""*) ok "authorized_keys: command=\"$G\"" ;; *) fail "authorized_keys: Forced Command fehlt" ;; esac
case "$k" in *'from="'*) ok "authorized_keys: from= gesetzt" ;; *) fail "authorized_keys: from= fehlt" ;; esac
case "$k" in *'<'*) fail "authorized_keys: Platzhalter <...> nicht ersetzt" ;; esac
case "$k" in *port-forwarding*) echo "HINWEIS port-forwarding erlaubt - nur auf Einstiegs-Host und noetigen Hops richtig" ;; esac
exit "$bad"
