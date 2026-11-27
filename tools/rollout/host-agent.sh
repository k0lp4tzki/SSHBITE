# sshbite-rollout host agent - the part of tools/rollout/sshbite-rollout that runs on one host, as root.
# POSIX sh. It is never started on its own: sshbite-rollout puts a header in front of this text (the
# variables below and the files of `sshbite collector export` as base64) and pipes the result into `sh -s`
# on the host - over the admin SSH connection, or directly when the host is the scanner machine itself.
#
# It does what docs/install.md "Zielhosts vorbereiten (installierter Collector)" tells the owner to do by
# hand, with three differences: it looks first and says what it would change (plan), it refuses instead of
# guessing when it finds something it did not create, and it checks the result (verify).
#
# Header variables (all validated by sshbite-rollout before they get here):
#   ACTION           check | plan | apply | verify | remove-plan | remove
#   AUDIT_USER       the audit account (audit.user)
#   VARIANT          A (entry host) | B (every other host) | C (hop for crawl.chain_fallback)
#   FROM             the from= value of the key line: addresses or CIDRs, comma separated
#   AK_LINE          the complete authorized_keys line ("" = not known yet: plan before the first build)
#   COLLECTOR_PATH   privilege.collector_path
#   HAVE_FILES       yes | no - no: the header has no files (plan before the first build)
#   ADOPT            yes | no - take over an account this script did not create
#   RM_FOREIGN       yes | no - move other sudoers.d files of the account into the backup
#   WANT_HOSTKEYS    yes | no - print the host keys of this sshd (entry host)
#   emit_file NAME   prints one exported file; EXPECT_<NAME> its SHA-256
#
# Output: one line per finding, "LEVEL<TAB>text". LEVEL is OK, INFO, WARN, PLAN (apply would do this),
# DONE (apply did this), FAIL, HOSTKEY or SUMMARY. Exit code 0: nothing failed. 1: at least one FAIL.
# Changes nothing in check, plan, verify and remove-plan.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 022

STATE=/var/lib/sshbite-rollout
SUDOERS_FILE=/etc/sudoers.d/sshbite
MARK_BEGIN='# BEGIN sshbite-rollout (docs/rollout.md) - do not edit between the markers'
MARK_END='# END sshbite-rollout'
DROPIN=/etc/ssh/sshd_config.d/99-sshbite-rollout.conf
LIBDIR=${COLLECTOR_PATH%/*}
GATE_PATH=$LIBDIR/sshbite-gate
RESOLVE_PATH=$LIBDIR/sshbite-resolve

FAILS=0
PLANS=0
WARNS=0
DONES=0
QUIET=no
MODE=plan          # plan | apply | verify: how todo() reads "this is not as it should be"
BACKUP=

out() { printf '%s\t%s\n' "$1" "$2"; }
ok() { [ "$QUIET" = yes ] || out OK "$1"; }
info() { [ "$QUIET" = yes ] || out INFO "$1"; }
warn() { WARNS=$((WARNS + 1)); [ "$QUIET" = yes ] || out WARN "$1"; }
fail() { FAILS=$((FAILS + 1)); out FAIL "$1"; }
done_() { DONES=$((DONES + 1)); out DONE "$1"; }
# todo TEXT: something is not as it should be. Returns 0 when the caller has to change it now.
todo() {
  case "$MODE" in
    plan) PLANS=$((PLANS + 1)); [ "$QUIET" = yes ] || out PLAN "$1"; return 1 ;;
    verify) fail "nicht ausgerollt: $1"; return 1 ;;
    apply) return 0 ;;
  esac
}

sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
owner_mode() { stat -c '%u %a' "$1" 2>/dev/null; }
# octal mode without a write bit for group or others?
no_go_write() { [ $((0$1 & 022)) -eq 0 ]; }
backup_dir() {
  if [ -z "$BACKUP" ]; then
    BACKUP=$STATE/backup/$(date -u +%Y%m%dT%H%M%SZ)
    install -d -m 0700 -o root -g root "$STATE" "$STATE/backup" "$BACKUP"
  fi
  printf '%s' "$BACKUP"
}
account_exists() { getent passwd "$AUDIT_USER" >/dev/null 2>&1; }
account_field() { getent passwd "$AUDIT_USER" | cut -d: -f"$1"; }
ours() { [ -f "$STATE/account" ] && [ "$(cat "$STATE/account" 2>/dev/null)" = "$AUDIT_USER" ]; }
# an account that was there before and that the owner let this script take over (--adopt-existing-account)
adopted() { [ -f "$STATE/adopted" ] && [ "$(cat "$STATE/adopted" 2>/dev/null)" = "$AUDIT_USER" ]; }
home_dir() {
  if account_exists; then account_field 6; else printf '/home/%s' "$AUDIT_USER"; fi
}
first_from() { printf '%s' "$FROM" | cut -d, -f1 | cut -d/ -f1; }
sshd_bin() { command -v sshd 2>/dev/null || echo /usr/sbin/sshd; }
# the effective sshd settings for one user, as sshd itself computes them
sshd_effective() {
  a=$(first_from)
  "$(sshd_bin)" -T -C "user=$1,host=$a,addr=$a" 2>/dev/null
}
word_in() {   # word_in WORD "list of words"
  for w in $2; do [ "$w" = "$1" ] && return 0; done
  return 1
}

# ---------------------------------------------------------------- prerequisites
prereq() {
  if [ "$(id -u)" != 0 ]; then
    fail "läuft nicht als root (uid $(id -u)): SSH_USER=root verwenden oder SSH_SUDO=yes mit sudo ohne Passwort"
    return
  fi
  os=unbekannt
  osid=
  if [ -r /etc/os-release ]; then
    os=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"' | head -n 1)
    osid=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"' | head -n 1)$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"' | cut -d. -f1 | head -n 1)
  fi
  case "$osid" in
    debian12 | almalinux9) info "System: $os (von SSHBITE getestet)" ;;
    *) info "System: $os (von SSHBITE nicht getestet: getestet sind Debian 12 und AlmaLinux 9)" ;;
  esac
  missing=
  for t in sudo visudo sshd ssh-keygen sha256sum base64 useradd usermod userdel passwd getent install awk stat sed; do
    command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
  done
  if [ -n "$missing" ]; then
    fail "fehlende Programme:$missing (Pakete: sudo, openssh-server, coreutils, shadow/passwd)"
  else
    ok "sudo, visudo, sshd und die Basiswerkzeuge sind vorhanden"
  fi
  if command -v setpriv >/dev/null 2>&1; then
    ok "setpriv (util-linux) ist vorhanden: $(command -v setpriv)"
  else
    fail "setpriv fehlt: Paket util-linux installieren (ohne setpriv liest der Collector nichts in Benutzer-Homes)"
  fi
  command -v timeout >/dev/null 2>&1 || info "timeout (coreutils) fehlt: das Gate läuft dann ohne Zeitlimit"
  v=$("$(sshd_bin)" -V 2>&1 | sed -n 's/.*OpenSSH_\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p' | head -n 1)
  if [ -n "$v" ]; then
    maj=${v% *}
    min=${v#* }
    if [ "$maj" -lt 7 ] || { [ "$maj" -eq 7 ] && [ "$min" -lt 8 ]; }; then
      fail "OpenSSH $maj.$min ist zu alt: die Schlüsselzeile braucht permitlisten (ab 7.8)"
    elif [ "$maj" -lt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -lt 7 ]; }; then
      warn "OpenSSH $maj.$min: älter als 8.7 ist von SSHBITE nicht getestet"
    else
      ok "OpenSSH $maj.$min"
    fi
  else
    warn "OpenSSH-Version nicht erkannt"
  fi
  if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = Enforcing ]; then
    warn "SELinux ist im Modus enforcing: von SSHBITE nicht getestet"
  fi
  main=/etc/sudoers
  [ -f "$main" ] || main=/usr/etc/sudoers
  if [ -f "$main" ] && grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers\.d/?[[:space:]]*$' "$main"; then
    ok "$main bindet /etc/sudoers.d ein"
  else
    fail "$main bindet /etc/sudoers.d nicht ein (Zeile '@includedir /etc/sudoers.d' fehlt): die sudo-Regel würde nicht gelten"
  fi
}

# ---------------------------------------------------------------- the audit account
DANGEROUS_GROUPS="root sudo wheel admin adm docker lxd lxc disk shadow systemd-journal libvirt kvm podman"

account_details() {
  h=$(account_field 6)
  n=0
  [ -d "$h" ] && n=$(find "$h" -mindepth 1 -maxdepth 3 2>/dev/null | wc -l)
  k=0
  [ -f "$h/.ssh/authorized_keys" ] && k=$(grep -cv '^[[:space:]]*\(#\|$\)' "$h/.ssh/authorized_keys" 2>/dev/null)
  p=$(ps -u "$AUDIT_USER" -o pid= 2>/dev/null | wc -l)
  printf 'uid %s, Shell %s, Gruppen "%s", Home %s mit %s Einträgen, %s Schlüsselzeile(n), %s laufende(r) Prozess(e)' \
    "$(account_field 3)" "$(account_field 7)" "$(id -Gn "$AUDIT_USER" 2>/dev/null)" "$h" "$n" "${k:-0}" "$p"
}

item_account() {
  if ! account_exists; then
    if todo "Konto $AUDIT_USER anlegen (eigene Gruppe, Shell /bin/sh, Home /home/$AUDIT_USER, Passwort gesperrt)"; then
      if getent group "$AUDIT_USER" >/dev/null 2>&1; then
        useradd -m -g "$AUDIT_USER" -s /bin/sh "$AUDIT_USER"
      else
        useradd -m -U -s /bin/sh "$AUDIT_USER"
      fi
      if account_exists; then
        install -d -m 0700 -o root -g root "$STATE"
        printf '%s\n' "$AUDIT_USER" > "$STATE/account"
        lock_password
        done_ "Konto $AUDIT_USER angelegt (uid $(account_field 3))"
      else
        fail "useradd für $AUDIT_USER ist fehlgeschlagen"
      fi
    fi
    return
  fi
  if [ "$(account_field 3)" = 0 ]; then
    fail "Konto $AUDIT_USER hat die uid 0: als Audit-Konto nicht zulässig"
    return
  fi
  if ours; then
    ok "Konto $AUDIT_USER ist vorhanden (von diesem Skript angelegt)"
  elif adopted; then
    ok "Konto $AUDIT_USER ist vorhanden (bei einem früheren Lauf übernommen)"
  elif [ "$ADOPT" = yes ]; then
    warn "Konto $AUDIT_USER gab es schon und wird übernommen (--adopt-existing-account): $(account_details)"
    if [ "$MODE" = apply ]; then
      install -d -m 0700 -o root -g root "$STATE"
      printf '%s\n' "$AUDIT_USER" > "$STATE/adopted"
    fi
  else
    fail "Konto $AUDIT_USER gibt es schon, und dieses Skript hat es nicht angelegt: $(account_details). Es würde sein Passwort sperren, Home und .ssh an root geben und authorized_keys ersetzen. Mit --adopt-existing-account übernehmen oder einen anderen AUDIT_USER wählen."
    return
  fi
  if [ "$(account_field 7)" != /bin/sh ]; then
    if todo "Shell von $AUDIT_USER auf /bin/sh setzen (ist $(account_field 7))"; then
      usermod -s /bin/sh "$AUDIT_USER" && done_ "Shell von $AUDIT_USER ist /bin/sh"
    fi
  fi
  pw=$(getent shadow "$AUDIT_USER" 2>/dev/null | cut -d: -f2)
  usepam=$("$(sshd_bin)" -T 2>/dev/null | awk '$1 == "usepam" {print $2}')
  case "$pw" in
    '!'*)
      # sshd without PAM treats a "!" hash as a locked account and refuses the key as well
      if [ "$usepam" = no ]; then
        if todo "Passwort von $AUDIT_USER von '!' auf '*' stellen (sshd läuft ohne PAM und lehnt '!'-gesperrte Konten ganz ab)"; then
          lock_password && done_ "Passwort von $AUDIT_USER ist gesperrt ('*')"
        fi
      else
        ok "Passwort von $AUDIT_USER ist gesperrt"
      fi ;;
    '*'*) ok "Passwort von $AUDIT_USER ist gesperrt" ;;
    *)
      if todo "Passwort von $AUDIT_USER sperren"; then
        lock_password && done_ "Passwort von $AUDIT_USER ist gesperrt"
      fi ;;
  esac
  primary=$(id -gn "$AUDIT_USER" 2>/dev/null)
  for g in $(id -Gn "$AUDIT_USER" 2>/dev/null); do
    [ "$g" = "$primary" ] && ! word_in "$g" "$DANGEROUS_GROUPS" && continue
    if word_in "$g" "$DANGEROUS_GROUPS"; then
      if [ "$g" = "$primary" ]; then
        fail "die Hauptgruppe von $AUDIT_USER ist $g: das gibt dem Konto Rechte ohne sudo. Von Hand ändern (usermod -g)."
      elif todo "$AUDIT_USER aus der Gruppe $g entfernen (gibt Rechte am Collector vorbei)"; then
        gpasswd -d "$AUDIT_USER" "$g" >/dev/null 2>&1 && done_ "$AUDIT_USER ist nicht mehr in der Gruppe $g"
      fi
    else
      warn "$AUDIT_USER ist zusätzlich in der Gruppe $g: prüfen, ob das nötig ist (gpasswd -d $AUDIT_USER $g)"
    fi
  done
  if command -v crontab >/dev/null 2>&1 && crontab -l -u "$AUDIT_USER" >/dev/null 2>&1; then
    warn "$AUDIT_USER hat eine crontab: prüfen und entfernen (crontab -r -u $AUDIT_USER)"
  fi
}

lock_password() {
  usepam=$("$(sshd_bin)" -T 2>/dev/null | awk '$1 == "usepam" {print $2}')
  if [ "$usepam" = no ]; then
    usermod -p '*' "$AUDIT_USER"
  else
    passwd -l "$AUDIT_USER" >/dev/null 2>&1 || usermod -p '*' "$AUDIT_USER"
  fi
}

# ---------------------------------------------------------------- collector, gate, resolve
item_files() {
  d=$LIBDIR
  chain=
  while [ -n "$d" ] && [ "$d" != / ]; do
    chain="$d $chain"
    d=${d%/*}
  done
  for d in / $chain; do
    [ -e "$d" ] || continue
    if [ -L "$d" ]; then
      # a symlink like /bin -> usr/bin is fine when root owns it: its target is checked through the path
      [ "$(stat -c %u "$d")" = 0 ] || fail "$d ist ein Symlink, der nicht root gehört"
      continue
    fi
    om=$(owner_mode "$d")
    if [ "${om% *}" != 0 ] || ! no_go_write "${om#* }"; then
      fail "$d gehört uid ${om% *} mit Modus ${om#* }: jedes Verzeichnis über dem Collector muss root gehören und darf für Gruppe und andere nicht schreibbar sein (sonst entspricht die sudo-Regel vollem Root-Zugriff). Rechte korrigieren oder COLLECTOR_PATH ändern."
    fi
  done
  if [ ! -d "$LIBDIR" ]; then
    if todo "Verzeichnis $LIBDIR anlegen (root:root 0755)"; then
      install -d -m 0755 -o root -g root "$LIBDIR" && done_ "$LIBDIR angelegt"
    fi
  fi
  for pair in "sshbite-collect:$COLLECTOR_PATH" "sshbite-gate:$GATE_PATH" "sshbite-resolve:$RESOLVE_PATH"; do
    name=${pair%%:*}
    dest=${pair#*:}
    if [ "$HAVE_FILES" != yes ]; then
      if [ -f "$dest" ]; then
        info "$dest ist vorhanden; der Abgleich mit dieser SSHBITE-Version ist erst nach dem Bau möglich"
      else
        PLANS=$((PLANS + 1))
        [ "$QUIET" = yes ] || out PLAN "$dest installieren"
      fi
      continue
    fi
    want=$(expect_sum "$name")
    if [ -L "$dest" ]; then
      fail "$dest ist ein Symlink: von Hand entfernen"
      continue
    fi
    have=
    [ -f "$dest" ] && have=$(sha "$dest")
    if [ "$have" = "$want" ] && [ "$(owner_mode "$dest")" = "0 755" ]; then
      ok "$dest ist aktuell (sha256 $(printf '%s' "$want" | cut -c1-12))"
      continue
    fi
    if [ -z "$have" ]; then
      text="$dest installieren (root:root 0755)"
    elif [ "$have" != "$want" ]; then
      text="$dest ersetzen (sha256 $(printf '%s' "$have" | cut -c1-12) -> $(printf '%s' "$want" | cut -c1-12))"
    else
      text="Besitzer und Modus von $dest auf root:root 0755 setzen"
    fi
    if todo "$text"; then
      tmp=$(mktemp "$STATE/tmp.XXXXXX") || { fail "mktemp in $STATE"; continue; }
      emit_file "$name" > "$tmp"
      if [ "$(sha "$tmp")" != "$want" ]; then
        fail "$name: Prüfsumme nach der Übertragung falsch"
        rm -f "$tmp"
        continue
      fi
      install -m 0755 -o root -g root "$tmp" "$dest" && done_ "$dest installiert"
      rm -f "$tmp"
    fi
  done
}

# ---------------------------------------------------------------- sudo
# the lines of a sudoers file that say something (no comments, no blank lines)
sudoers_lines() { grep -Ev '^[[:space:]]*(#([^i]|$)|#i[^n]|$)' "$1" 2>/dev/null; }
# a rule or a Defaults line for the account itself, or an alias that names it
mentions_user() {
  grep -Eq "^[[:space:]]*(Defaults:)?$AUDIT_USER([[:space:],]|\$)|^[[:space:]]*User_Alias[[:space:]].*[=,[:space:]]$AUDIT_USER([[:space:],]|\$)"
}

item_sudoers() {
  main=/etc/sudoers
  [ -f "$main" ] || main=/usr/etc/sudoers
  GLOBAL_ALL=no
  if [ -f "$main" ]; then
    if sudoers_lines "$main" | grep -Eq '^ALL[[:space:]]+ALL[[:space:]]*=[[:space:]]*\(ALL(:ALL)?\)[[:space:]]*ALL[[:space:]]*(#.*)?$'; then
      GLOBAL_ALL=yes
      warn "$main enthält 'ALL ALL=(ALL) ALL' (SUSE-Standard mit 'Defaults targetpw'): jeder Benutzer darf mit dem root-Passwort alles ausführen, also auch $AUDIT_USER. Der Audit-Schlüssel kann das nicht nutzen (das Gate lässt nur drei feste Befehle zu), 'sudo -l -U $AUDIT_USER' zeigt die Regel aber an. Empfohlen: beide Zeilen in $main auskommentieren - das betrifft alle Benutzer und bleibt deshalb Ihre Entscheidung."
    fi
    hit=$(sudoers_lines "$main" | grep -Ev '^[[:space:]]*Defaults' | mentions_user_lines)
    [ -z "$hit" ] || fail "$main enthält eine eigene Regel für $AUDIT_USER: von Hand entfernen: $hit"
  fi
  for f in /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    [ "$f" = "$SUDOERS_FILE" ] && continue
    case "${f##*/}" in *.* | *~) continue ;; esac     # sudo ignores these names
    sudoers_lines "$f" | mentions_user || continue
    other=$(sudoers_lines "$f" | grep -Evc "^[[:space:]]*(Defaults:)?$AUDIT_USER([[:space:]]|\$)")
    if [ "$other" != 0 ]; then
      fail "$f enthält Regeln für $AUDIT_USER und $other andere Zeile(n): die Zeilen für $AUDIT_USER von Hand entfernen"
    elif [ "$RM_FOREIGN" = yes ]; then
      if todo "$f (nur Regeln für $AUDIT_USER, $(sudoers_lines "$f" | wc -l) Zeile(n)) in das Backup verschieben"; then
        b=$(backup_dir)
        mv "$f" "$b/sudoers.d-${f##*/}" && done_ "$f nach $b verschoben"
      fi
    else
      fail "$f enthält eine andere sudo-Regel für $AUDIT_USER ($(sudoers_lines "$f" | head -n 1)): damit bliebe der Audit-Schlüssel mächtiger als der Collector. Mit --remove-foreign-sudoers verschiebt das Skript die Datei in ein Backup."
    fi
  done
  if [ "$HAVE_FILES" != yes ]; then
    [ -f "$SUDOERS_FILE" ] || { PLANS=$((PLANS + 1)); [ "$QUIET" = yes ] || out PLAN "$SUDOERS_FILE installieren"; }
    return
  fi
  want=$(expect_sum sudoers.d-sshbite)
  have=
  [ -f "$SUDOERS_FILE" ] && have=$(sha "$SUDOERS_FILE")
  if [ "$have" = "$want" ] && [ "$(owner_mode "$SUDOERS_FILE")" = "0 440" ]; then
    ok "$SUDOERS_FILE ist aktuell"
  else
    if [ -z "$have" ]; then text="$SUDOERS_FILE installieren (eine Regel: $AUDIT_USER darf $COLLECTOR_PATH als root starten, ohne Argumente)"
    else text="$SUDOERS_FILE ersetzen"; fi
    if todo "$text"; then
      tmp=$(mktemp "$STATE/tmp.XXXXXX") || { fail "mktemp in $STATE"; return; }
      emit_file sudoers.d-sshbite > "$tmp"
      if [ "$(sha "$tmp")" != "$want" ]; then
        fail "sudoers.d-sshbite: Prüfsumme nach der Übertragung falsch"
      elif ! visudo -cf "$tmp" >/dev/null 2>&1; then
        fail "visudo lehnt die sudo-Regel ab: $(visudo -cf "$tmp" 2>&1 | head -n 1)"
      else
        [ -z "$have" ] || cp -p "$SUDOERS_FILE" "$(backup_dir)/sudoers.d-sshbite"
        install -m 0440 -o root -g root "$tmp" "$SUDOERS_FILE" && done_ "$SUDOERS_FILE installiert"
      fi
      rm -f "$tmp"
    fi
  fi
}
mentions_user_lines() {
  while IFS= read -r line; do
    printf '%s\n' "$line" | mentions_user && printf '%s; ' "$line"
  done
}

# what sudo itself says the account may do: exactly the collector
check_sudo_effective() {
  account_exists || return 0
  [ -f "$SUDOERS_FILE" ] || return 0
  list=$(sudo -l -U "$AUDIT_USER" 2>&1 | awk 'f && NF {sub(/^[[:space:]]+/, ""); print} /may run the following commands/ {f = 1}')
  want="(root) NOPASSWD: $COLLECTOR_PATH \"\""
  found=no
  extra=
  later_all=no
  old_ifs=$IFS
  IFS='
'
  for line in $list; do
    if [ "$line" = "$want" ]; then
      found=yes
      later_all=no
    elif [ "$GLOBAL_ALL" = yes ] && { [ "$line" = "(ALL) ALL" ] || [ "$line" = "(ALL : ALL) ALL" ]; }; then
      later_all=$found
    else
      extra="$extra$line; "
    fi
  done
  IFS=$old_ifs
  if [ "$found" != yes ]; then
    fail "sudo -l -U $AUDIT_USER nennt die Collector-Regel nicht: $(sudo -l -U "$AUDIT_USER" 2>&1 | tail -n 1)"
  elif [ "$later_all" = yes ]; then
    # sudo takes the last rule that matches: listed after the collector rule, 'ALL ALL=(ALL) ALL' wins,
    # and sudo asks for a password where SSHBITE never sends one
    fail "die Regel 'ALL ALL=(ALL) ALL' steht in der sudoers-Datei hinter '@includedir /etc/sudoers.d' und überstimmt damit die Collector-Regel (sudo nimmt die letzte passende Regel): sudo würde $AUDIT_USER nach einem Passwort fragen, und der Scan meldet 'sudo asks for a password'. Die Regel vor die includedir-Zeile setzen oder entfernen."
  elif [ -n "$extra" ]; then
    fail "sudo -l -U $AUDIT_USER nennt außer dem Collector noch: $extra"
  elif [ "$GLOBAL_ALL" = yes ]; then
    ok "sudo -l -U $AUDIT_USER: der Collector und die globale Regel 'ALL ALL=(ALL) ALL' (siehe Warnung)"
  else
    ok "sudo -l -U $AUDIT_USER nennt nur den Collector"
  fi
}

# ---------------------------------------------------------------- home, .ssh, authorized_keys
BAD_HOMES="/ /root /home /var /var/lib /var/empty /var/run /run /tmp /etc /usr /bin /sbin /dev /proc /sys /nonexistent /opt /srv /boot"

item_sshdir() {
  h=$(home_dir)
  if word_in "$h" "$BAD_HOMES" || [ -z "$h" ]; then
    fail "das Home von $AUDIT_USER ist '$h': dort kann keine eigene authorized_keys liegen. Ein Konto mit eigenem Home verwenden."
    return
  fi
  if ! account_exists; then
    PLANS=$((PLANS + 2))
    [ "$QUIET" = yes ] || {
      out PLAN "$h und $h/.ssh an root geben (0755): das Konto kann seine Schlüssel nicht selbst ändern"
      out PLAN "$h/.ssh/authorized_keys schreiben (root:root 0644, eine Zeile, Variante $VARIANT, from=\"$FROM\")"
    }
    return
  fi
  if [ -L "$h" ] || { [ -e "$h" ] && [ ! -d "$h" ]; }; then
    fail "$h ist kein Verzeichnis"
    return
  fi
  if [ ! -d "$h" ]; then
    if todo "$h anlegen (root:root 0755)"; then
      install -d -m 0755 -o root -g root "$h" && done_ "$h angelegt"
    fi
  elif [ "$(owner_mode "$h")" != "0 755" ] || [ "$(stat -c %g "$h")" != 0 ]; then
    if todo "$h an root geben (root:root 0755; ist uid $(stat -c '%u, Modus %a' "$h"))"; then
      chown root:root "$h" && chmod 0755 "$h" && done_ "$h gehört root (0755)"
    fi
  fi
  s=$h/.ssh
  if [ -L "$s" ] || { [ -e "$s" ] && [ ! -d "$s" ]; }; then
    fail "$s ist kein Verzeichnis (Symlink oder Datei): von Hand entfernen"
    return
  fi
  if [ ! -d "$s" ]; then
    if todo "$s anlegen (root:root 0755)"; then
      install -d -m 0755 -o root -g root "$s" && done_ "$s angelegt"
    fi
  elif [ "$(owner_mode "$s")" != "0 755" ] || [ "$(stat -c %g "$s")" != 0 ]; then
    if todo "$s an root geben (root:root 0755)"; then
      chown root:root "$s" && chmod 0755 "$s" && done_ "$s gehört root (0755)"
    fi
  fi
  if [ -d "$s" ]; then
    others=$(find "$s" -mindepth 1 -maxdepth 1 ! -name authorized_keys 2>/dev/null | sed 's|.*/||' | tr '\n' ' ')
    if [ -n "$others" ]; then
      n=$(printf '%s' "$others" | wc -w)
      if todo "$n weitere(n) Eintrag/Einträge aus $s in das Backup verschieben: $others(sshd liest dort z. B. auch authorized_keys2 - ohne command= und from=)"; then
        b=$(backup_dir)
        install -d -m 0700 -o root -g root "$b/dot-ssh"
        for o in $others; do mv "$s/$o" "$b/dot-ssh/"; done
        done_ "$n Eintrag/Einträge aus $s nach $b/dot-ssh verschoben"
      fi
    fi
  fi
  ak=$s/authorized_keys
  if [ -z "$AK_LINE" ]; then
    info "$ak: der Abgleich der Schlüsselzeile ist erst nach dem Bau möglich"
    return
  fi
  if [ -L "$ak" ] || { [ -e "$ak" ] && [ ! -f "$ak" ]; }; then
    fail "$ak ist keine normale Datei: von Hand entfernen"
    return
  fi
  if [ -f "$ak" ] && [ "$(cat "$ak")" = "$AK_LINE" ] && [ "$(owner_mode "$ak")" = "0 644" ]; then
    ok "$ak enthält genau die Schlüsselzeile der Variante $VARIANT mit from=\"$FROM\""
    return
  fi
  if [ -f "$ak" ]; then
    k=$(grep -cv '^[[:space:]]*\(#\|$\)' "$ak" 2>/dev/null)
    text="$ak ersetzen (bisher ${k:-0} Schlüsselzeile(n), kommt ins Backup): eine Zeile, Variante $VARIANT, from=\"$FROM\""
  else
    text="$ak schreiben (root:root 0644, eine Zeile, Variante $VARIANT, from=\"$FROM\")"
  fi
  if todo "$text"; then
    [ ! -f "$ak" ] || cp -p "$ak" "$(backup_dir)/authorized_keys"
    tmp=$(mktemp "$STATE/tmp.XXXXXX") || { fail "mktemp in $STATE"; return; }
    printf '%s\n' "$AK_LINE" > "$tmp"
    install -m 0644 -o root -g root "$tmp" "$ak" && done_ "$ak geschrieben"
    rm -f "$tmp"
  fi
}

# ---------------------------------------------------------------- sshd
item_sshd() {
  sb=$(sshd_bin)
  if ! "$sb" -t >/dev/null 2>&1; then
    fail "sshd -t meldet schon jetzt einen Fehler in der Konfiguration: $("$sb" -t 2>&1 | head -n 1)"
    return
  fi
  eff=$(sshd_effective "$AUDIT_USER")
  if [ -z "$eff" ]; then
    fail "sshd -T liefert keine Einstellungen"
    return
  fi
  get() { printf '%s\n' "$eff" | awk -v k="$1" '$1 == k {$1 = ""; sub(/^ /, ""); print}'; }
  [ "$(get pubkeyauthentication)" = yes ] || fail "sshd: PubkeyAuthentication ist nicht yes"
  [ "$(get permituserenvironment)" = no ] || fail "sshd: PermitUserEnvironment ist nicht no: ~/.ssh/environment würde gelesen"
  for e in $(get acceptenv); do
    case "$e" in
      LANG | LC_* | LANGUAGE | XMODIFIERS) ;;
      '*' | PATH | LD_* | BASH_ENV | ENV | IFS) fail "sshd: AcceptEnv $e erlaubt es dem Client, das Gate zu beeinflussen" ;;
      *) warn "sshd: AcceptEnv $e - üblich sind nur LANG und LC_*" ;;
    esac
  done
  akf=$(get authorizedkeysfile)
  std=no
  for f in $akf; do
    # shellcheck disable=SC2088  # the literal text of a sshd_config value, not a path to expand
    case "$f" in
      .ssh/authorized_keys | %h/.ssh/authorized_keys | '~/.ssh/authorized_keys') std=yes ;;
      .ssh/* | %h/.ssh/* | '~/.ssh/'*) ;;     # inside .ssh: item_sshdir clears everything but authorized_keys
      /*)
        p=$(printf '%s' "$f" | sed "s|%u|$AUDIT_USER|g; s|%h|$(home_dir)|g")
        [ ! -e "$p" ] || fail "sshd liest für $AUDIT_USER auch $p (AuthorizedKeysFile $f): von Hand prüfen und entfernen"
        ;;
      *)
        [ ! -e "$(home_dir)/$f" ] || fail "sshd liest für $AUDIT_USER auch $(home_dir)/$f (AuthorizedKeysFile $f): von Hand prüfen und entfernen"
        ;;
    esac
  done
  [ "$std" = yes ] || fail "sshd: AuthorizedKeysFile ($akf) enthält .ssh/authorized_keys nicht: dieser Aufbau wird nicht unterstützt"
  akc=$(get authorizedkeyscommand)
  case "$akc" in '' | none) ;; *) warn "sshd: AuthorizedKeysCommand $akc liefert weitere Schlüssel: prüfen, dass es für $AUDIT_USER keine gibt" ;; esac
  au=$(get allowusers | tr '\n' ' ')
  if [ -n "$au" ]; then
    hit=no
    for u in $au; do case "${u%%@*}" in "$AUDIT_USER" | '*') hit=yes ;; esac; done
    [ "$hit" = yes ] || fail "sshd: AllowUsers ($au) nennt $AUDIT_USER nicht: in sshd_config aufnehmen, sonst lehnt sshd die Anmeldung ab"
  fi
  ag=$(get allowgroups | tr '\n' ' ')
  if [ -n "$ag" ]; then
    hit=no
    mine=$AUDIT_USER
    account_exists && mine=$(id -Gn "$AUDIT_USER" 2>/dev/null)
    for g in $ag; do { [ "$g" = '*' ] || word_in "$g" "$mine"; } && hit=yes; done
    [ "$hit" = yes ] || fail "sshd: AllowGroups ($ag) enthält keine Gruppe von $AUDIT_USER: in sshd_config aufnehmen, sonst lehnt sshd die Anmeldung ab"
  fi
  for u in $(get denyusers); do
    [ "${u%%@*}" != "$AUDIT_USER" ] || fail "sshd: DenyUsers nennt $AUDIT_USER"
  done
  [ "$VARIANT" = B ] && return
  # entry host and hops: forwarding to SSH ports only, no listener on a unix socket
  if [ "$(get allowtcpforwarding)" = local ] && [ "$(get allowstreamlocalforwarding)" = no ]; then
    ok "sshd: für $AUDIT_USER gilt AllowTcpForwarding local und AllowStreamLocalForwarding no"
    return
  fi
  if [ -f /etc/ssh/sshd_config ]; then
    target=/etc/ssh/sshd_config
  elif [ -d /etc/ssh/sshd_config.d ]; then
    target=$DROPIN
  else
    fail "weder /etc/ssh/sshd_config noch /etc/ssh/sshd_config.d gefunden: den Block 'Match User $AUDIT_USER' von Hand eintragen"
    return
  fi
  if todo "sshd: Block 'Match User $AUDIT_USER' (AllowTcpForwarding local, AllowStreamLocalForwarding no) in $target eintragen, prüfen und sshd neu laden"; then
    b=$(backup_dir)
    before=$(sshd_effective root)
    if [ -f "$target" ]; then cp -p "$target" "$b/${target##*/}"; had=yes; else had=no; fi
    strip_block "$target"
    {
      [ ! -s "$target" ] || printf '\n'
      printf '%s\n' "$MARK_BEGIN"
      printf 'Match User %s\n    AllowTcpForwarding local\n    AllowStreamLocalForwarding no\n' "$AUDIT_USER"
      printf '%s\n' "$MARK_END"
    } >> "$target"
    [ "$had" = yes ] || chmod 0600 "$target"
    eff=$(sshd_effective "$AUDIT_USER")
    good=yes
    "$sb" -t >/dev/null 2>&1 || good="sshd -t lehnt die Konfiguration ab"
    [ "$good" != yes ] || [ "$(sshd_effective root)" = "$before" ] || good="der Block ändert auch die Einstellungen anderer Konten"
    [ "$good" != yes ] || { [ "$(get allowtcpforwarding)" = local ] && [ "$(get allowstreamlocalforwarding)" = no ]; } \
      || good="der Block wirkt für $AUDIT_USER nicht (ein früherer Match-Block setzt die Werte schon)"
    if [ "$good" != yes ]; then
      if [ "$had" = yes ]; then cp -p "$b/${target##*/}" "$target"; else rm -f "$target"; fi
      fail "sshd: $good - $target ist wieder im alten Zustand. Den Block von Hand eintragen."
      return
    fi
    done_ "sshd: Block für $AUDIT_USER steht in $target (alte Fassung in $b)"
    reload_sshd
  fi
}

# remove our block from FILE (and the file, if it was only our drop-in)
strip_block() {
  [ -f "$1" ] || return 0
  grep -qF "$MARK_BEGIN" "$1" || return 0
  tmp=$(mktemp "$STATE/tmp.XXXXXX") || return 1
  awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
    $0 == b {skip = 1; next}
    $0 == e {skip = 0; next}
    !skip {lines[++n] = $0}
    END {while (n > 0 && lines[n] == "") n--; for (i = 1; i <= n; i++) print lines[i]}' "$1" > "$tmp"
  cat "$tmp" > "$1"
  rm -f "$tmp"
}

reload_sshd() {
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    for unit in sshd ssh; do
      if systemctl is-active --quiet "$unit" 2>/dev/null; then
        if systemctl reload "$unit" 2>/dev/null; then done_ "sshd neu geladen (systemctl reload $unit)"; else fail "systemctl reload $unit ist fehlgeschlagen"; fi
        return
      fi
    done
  fi
  for pf in /run/sshd.pid /var/run/sshd.pid; do
    pid=$(cat "$pf" 2>/dev/null)
    if [ -n "$pid" ] && kill -HUP "$pid" 2>/dev/null; then
      done_ "sshd neu geladen (HUP an pid $pid)"
      return
    fi
  done
  warn "sshd läuft hier nicht als systemd-Dienst und hat keine pid-Datei: bitte von Hand neu laden"
}

print_hostkeys() {
  "$(sshd_bin)" -T 2>/dev/null | awk '$1 == "hostkey" {print $2}' | while IFS= read -r k; do
    [ -r "$k.pub" ] || continue
    t=$(cut -d' ' -f1 "$k.pub")
    case "$t" in ssh-ed25519 | ecdsa-sha2-* | ssh-rsa) out HOSTKEY "$(cut -d' ' -f1,2 "$k.pub")" ;; esac
  done
}

# ---------------------------------------------------------------- remove
item_remove() {
  doit=$1
  h=$(home_dir)
  rm_one() {     # rm_one PATH TEXT
    [ -e "$1" ] || [ -L "$1" ] || return 0
    if [ "$doit" = yes ]; then rm -f "$1" && done_ "$1 entfernt"; else PLANS=$((PLANS + 1)); out PLAN "$1 entfernen ($2)"; fi
  }
  rm_one "$SUDOERS_FILE" "die sudo-Regel"
  rm_one "$COLLECTOR_PATH" "der Collector"
  rm_one "$GATE_PATH" "das Gate"
  rm_one "$RESOLVE_PATH" "die Namensauflösung"
  if [ -d "$LIBDIR" ] && [ "$doit" = yes ]; then
    rmdir "$LIBDIR" 2>/dev/null && done_ "$LIBDIR entfernt"
  fi
  account_exists && rm_one "$h/.ssh/authorized_keys" "die Schlüsselzeile"
  for target in /etc/ssh/sshd_config "$DROPIN"; do
    [ -f "$target" ] && grep -qF "$MARK_BEGIN" "$target" || continue
    if [ "$doit" != yes ]; then
      PLANS=$((PLANS + 1))
      out PLAN "sshd: Block 'Match User' aus $target entfernen und sshd neu laden"
      continue
    fi
    b=$(backup_dir)
    cp -p "$target" "$b/${target##*/}"
    strip_block "$target"
    [ "$target" = "$DROPIN" ] && [ ! -s "$target" ] && rm -f "$target"
    if "$(sshd_bin)" -t >/dev/null 2>&1; then
      done_ "sshd: Block aus $target entfernt"
      reload_sshd
    else
      cp -p "$b/${target##*/}" "$target"
      fail "sshd -t lehnt die Konfiguration ohne den Block ab: $target ist wieder im alten Zustand"
    fi
  done
  if account_exists; then
    if ours; then
      if [ "$doit" = yes ]; then
        rmdir "$h/.ssh" 2>/dev/null
        if userdel "$AUDIT_USER" 2>/dev/null; then
          done_ "Konto $AUDIT_USER entfernt"
          getent group "$AUDIT_USER" >/dev/null 2>&1 && groupdel "$AUDIT_USER" 2>/dev/null
          if rmdir "$h" 2>/dev/null; then done_ "$h entfernt"
          elif [ -d "$h" ]; then
            # what useradd copied from /etc/skel is all that can be left in a home we created
            left=$(find "$h" -mindepth 1 2>/dev/null | wc -l)
            b=$(backup_dir)
            mv "$h" "$b/home" && done_ "$h ($left Einträge aus /etc/skel) nach $b/home verschoben"
          fi
        else
          fail "userdel $AUDIT_USER ist fehlgeschlagen (läuft noch ein Prozess des Kontos?)"
        fi
        rm -f "$STATE/account"
      else
        PLANS=$((PLANS + 1))
        out PLAN "Konto $AUDIT_USER und $h entfernen (von diesem Skript angelegt)"
      fi
    else
      info "Konto $AUDIT_USER bleibt: dieses Skript hat es nicht angelegt. $h gehört weiter root (ggf. chown $AUDIT_USER $h)."
      [ "$doit" != yes ] || rm -f "$STATE/adopted"
    fi
  fi
  [ -d "$STATE/backup" ] && info "Backups früherer Läufe bleiben in $STATE/backup"
}

# ---------------------------------------------------------------- run
run_items() {
  item_account
  item_files
  item_sudoers
  item_sshdir
  item_sshd
}

summary() { out SUMMARY "$FAILS $PLANS $WARNS $DONES"; }

prereq
if [ "$FAILS" -gt 0 ] || [ "$ACTION" = check ]; then
  summary
  [ "$FAILS" -eq 0 ]
  exit
fi

case "$ACTION" in
  plan)
    MODE=plan
    run_items
    check_sudo_effective
    [ "$WANT_HOSTKEYS" = yes ] && print_hostkeys
    ;;
  verify)
    MODE=verify
    run_items
    check_sudo_effective
    [ "$WANT_HOSTKEYS" = yes ] && print_hostkeys
    ;;
  apply)
    # 1. look only: anything that needs a person stops the host before the first change
    MODE=plan
    QUIET=yes
    run_items
    if [ "$FAILS" -gt 0 ]; then
      out INFO "nichts geändert: erst die FAIL-Punkte klären"
      summary
      exit 1
    fi
    # 2. change
    FAILS=0 PLANS=0 WARNS=0
    QUIET=no
    MODE=apply
    install -d -m 0700 -o root -g root "$STATE"
    run_items
    # 3. look again: everything must now be as planned
    if [ "$FAILS" -eq 0 ]; then
      WARNS=0
      MODE=verify
      QUIET=yes
      run_items
      QUIET=no
      check_sudo_effective
    fi
    [ "$WANT_HOSTKEYS" = yes ] && print_hostkeys
    ;;
  remove-plan) item_remove no ;;
  remove)
    install -d -m 0700 -o root -g root "$STATE"
    item_remove yes
    ;;
  *) fail "unbekannte Aktion $ACTION" ;;
esac
summary
[ "$FAILS" -eq 0 ]
