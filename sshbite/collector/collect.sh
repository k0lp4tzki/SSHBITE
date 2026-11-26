LC_ALL=C; export LC_ALL; PATH=/usr/sbin:/usr/bin:/sbin:/bin; set -u
B=2d534dece3d8
# SSHBITE collector. Fixed, read-only POSIX sh script, sent verbatim on stdin.
# It reads files and prints records to stdout. It writes no file, starts no
# network connection and builds no command from target data. B above is the
# short SHA-256 of everything after the line "B=..." (checked by the tool).
T='	'
NL='
'
NSEC=0
FSIZE=0
ROOT=0
ASU=0
uid=''
gid=''
printf '#SSHBITE 1 %s\n' "$B"

sec() {
  NSEC=$((NSEC + 1))
  printf '#S %s\n' "$1"
}

val() {
  printf '#V %s\t%s\n' "$1" "$2"
}

# ---- reads in user homes run as the account (setpriv, util-linux), never as root
# ASU=1 while USERS handles an account with uid != 0 and the collector runs as root: every
# read below (ls, stat, head, test -r, ssh-keygen) then runs with that account's uid, gid and
# groups, like sshd reads authorized_keys. A file or ~/.ssh swapped for a symlink therefore
# yields only what the account may read itself. ASU=0: as the collector (system files; or
# the collector is not root; or the account is uid 0).
uls() {
  if [ "$ASU" = 1 ]; then
    setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs -- ls -A -- "$1"
  else
    ls -A -- "$1"
  fi
}

ustat() {
  if [ "$ASU" = 1 ]; then
    setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs -- stat -c '%u %U %a %Y %s' -- "$1"
  else
    stat -c '%u %U %a %Y %s' -- "$1"
  fi
}

ulsnd() {
  if [ "$ASU" = 1 ]; then
    setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs -- ls -lnd -- "$1"
  else
    ls -lnd -- "$1"
  fi
}

# uhead N PATH
uhead() {
  if [ "$ASU" = 1 ]; then
    setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs -- head -n "$1" -- "$2"
  else
    head -n "$1" -- "$2"
  fi
}

# utest -r|-x PATH - the external test(1), so that it runs as the account
utest() {
  if [ "$ASU" = 1 ]; then
    setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs -- test "$1" "$2"
  else
    test "$1" "$2"
  fi
}

# ukg y|l PATH - ssh-keygen -y (public half) or -l (fingerprint), output and exit status
ukg() {
  if [ "$1" = y ]; then
    if [ "$ASU" = 1 ]; then
      setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs -- ssh-keygen -y -P '' -f "$2" </dev/null 2>&1
    else
      ssh-keygen -y -P '' -f "$2" </dev/null 2>&1
    fi
  elif [ "$ASU" = 1 ]; then
    setpriv --reuid="$uid" --regid="$gid" --init-groups --no-new-privs -- ssh-keygen -l -f "$2" </dev/null 2>&1
  else
    ssh-keygen -l -f "$2" </dev/null 2>&1
  fi
}

# unr - the reason for a file that cannot be read: as the account, or as the collector
unr() {
  if [ "$ASU" = 1 ]; then
    printf 'unreadable by account'
  else
    printf 'unreadable'
  fi
}

# fhdr PATH ACCOUNT - file header record; sets FSIZE
fhdr() {
  st=$(ustat "$1" 2>/dev/null) || st=$(ulsnd "$1" 2>/dev/null | awk '{print $3 " ? " $1 " 0 " $5}')
  set -f
  set -- "$1" "$2" $st
  set +f
  printf '#F %s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "${3:-?}" "${4:-?}" "${5:-?}" "${6:-?}" "${7:-0}" "$2"
  FSIZE=${7:-0}
}

# content PATH - prefixed content lines of a regular file, after fhdr
content() {
  if [ "$FSIZE" -gt 1048576 ] 2>/dev/null; then
    printf '#X %s\ttoo large\n' "$1"
    return
  fi
  if ! utest -r "$1"; then
    printf '#X %s\t%s\n' "$1" "$(unr)"
    return
  fi
  uhead 5000 "$1" 2>/dev/null | sed 's/^/|/'
  printf '\n'
}

# kg PATH MODE RC OUTPUT - ssh-keygen result records (at most 2 lines: the last two, so that a
# warning banner - e.g. "UNPROTECTED PRIVATE KEY FILE" when run as the owner - does not hide the result)
kg() {
  printf '%s\n' "$4" | awk 'NF {a = b; b = $0; n++} END {if (n > 1) print a; if (n > 0) print b}' | while IFS= read -r l; do
    printf '#K %s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$l"
  done
}

# privkey PATH - header line and public half of a private key, never its content
privkey() {
  if [ "$FSIZE" -gt 65536 ] 2>/dev/null; then
    return
  fi
  if ! utest -r "$1"; then
    printf '#X %s\t%s\n' "$1" "$(unr)"
    return
  fi
  h=$(uhead 1 "$1" 2>/dev/null | head -c 200)
  case "$h" in
    *'PRIVATE KEY-----'* | *PuTTY-User-Key-File*) ;;
    *) return ;;
  esac
  printf '#H %s\t%s\n' "$1" "$h"
  o=$(ukg y "$1")
  kg "$1" y "$?" "$o"
  o=$(ukg l "$1")
  kg "$1" l "$?" "$o"
}

# akexpand PATTERN HOME USER UID - expand %h %u %U %% ; relative = below home
akexpand() {
  P="$1" H="$2" U="$3" I="$4" awk 'BEGIN {
    s = ENVIRON["P"]; out = ""
    while ((i = index(s, "%")) > 0) {
      out = out substr(s, 1, i - 1); c = substr(s, i + 1, 1)
      if (c == "h") out = out ENVIRON["H"]
      else if (c == "u") out = out ENVIRON["U"]
      else if (c == "U") out = out ENVIRON["I"]
      else if (c == "%") out = out "%"
      else out = out "%" c
      s = substr(s, i + 2)
    }
    out = out s
    if (substr(out, 1, 1) != "/") out = ENVIRON["H"] "/" out
    print out
  }'
}

# ---------------------------------------------------------------- META
sec META
val hostname "$(hostname 2>/dev/null)"
val uname "$(uname -srm 2>/dev/null)"
val uid "$(id -u 2>/dev/null)"
if [ "$(id -u 2>/dev/null)" = 0 ]; then
  ROOT=1
fi
# setpriv: yes/no as root, n/a otherwise (the collector then reads everything as itself anyway)
SETPRIV=n/a
if [ "$ROOT" = 1 ]; then
  if [ -x /usr/bin/setpriv ] || [ -x /bin/setpriv ]; then
    SETPRIV=yes
  else
    SETPRIV=no
  fi
fi
val setpriv "$SETPRIV"
val cmd os-release
head -n 20 /etc/os-release 2>/dev/null | sed 's/^/|/'
printf '\n'
val cmd ip-addr
o=$(ip -o addr show 2>/dev/null) || o=$(hostname -I 2>/dev/null) || o=$(ifconfig -a 2>/dev/null)
printf '%s\n' "$o" | sed 's/^/|/'
printf '\n'

# ---------------------------------------------------------------- HOSTKEYS
sec HOSTKEYS
for f in /etc/ssh/ssh_host_*_key.pub; do
  [ -f "$f" ] || continue
  fhdr "$f" ""
  content "$f"
done

# ---------------------------------------------------------------- SSHD
sec SSHD
SSHDT=$(/usr/sbin/sshd -T 2>/dev/null)
val sshd_t_lines "$(printf '%s\n' "$SSHDT" | awk 'NF > 0 {n++} END {print n + 0}')"
val cmd sshd-T
printf '%s\n' "$SSHDT" | sed 's/^/|/'
printf '\n'
if [ -f /etc/ssh/sshd_config ]; then
  fhdr /etc/ssh/sshd_config ""
  content /etc/ssh/sshd_config
fi
INCS=$(awk 'tolower($1) == "include" {for (i = 2; i <= NF; i++) print $i}' /etc/ssh/sshd_config 2>/dev/null)
n=0
set -f
for pat in $INCS; do
  case "$pat" in
    /*) ;;
    *) pat="/etc/ssh/$pat" ;;
  esac
  set +f
  for f in $pat; do
    [ -f "$f" ] || continue
    n=$((n + 1))
    [ "$n" -le 20 ] || break
    fhdr "$f" ""
    content "$f"
  done
  set -f
done
set +f

AKF=$(printf '%s\n' "$SSHDT" | awk '$1 == "authorizedkeysfile" {$1 = ""; sub(/^ +/, ""); print; exit}')
if [ -z "$AKF" ]; then
  AKF=$(awk 'tolower($1) == "match" {exit} tolower($1) == "authorizedkeysfile" {$1 = ""; sub(/^[ \t]+/, ""); print; exit}' /etc/ssh/sshd_config 2>/dev/null)
fi
[ -n "$AKF" ] || AKF='.ssh/authorized_keys .ssh/authorized_keys2'
val authorizedkeysfile "$AKF"

# ---------------------------------------------------------------- ACCOUNTS
sec ACCOUNTS
PW=$(getent passwd 2>/dev/null | head -n 20000)
[ -n "$PW" ] || PW=$(head -n 20000 /etc/passwd 2>/dev/null)
val cmd passwd
printf '%s\n' "$PW" | sed 's/^/|/'
printf '\n'

# ---------------------------------------------------------------- SHADOW
if [ "$(id -u 2>/dev/null)" = 0 ]; then
  sec SHADOW
  val cmd shadow
  awk -F: '{print $1":"substr($2,1,1)":"$8}' /etc/shadow 2>/dev/null | sed 's/^/|/'
  printf '\n'
fi

# ---------------------------------------------------------------- USERS
sec USERS
printf '%s\n' "$PW" | {
  cnt=0
  while IFS=: read -r u x uid gid gecos home shell; do
    [ -n "$u" ] || continue
    [ -n "$home" ] || continue
    case "$u$home" in
      *"$T"*) continue ;;
    esac
    akfs=''
    if [ "$AKF" != none ]; then
      set -f
      for p in $AKF; do
        akfs="$akfs$(akexpand "$p" "$home" "$u" "$uid")$NL"
      done
      set +f
    fi
    has=0
    [ -d "$home/.ssh" ] && has=1
    if [ "$has" = 0 ]; then
      has=$(printf '%s' "$akfs" | {
        r=0
        while IFS= read -r p; do
          [ -n "$p" ] && [ -e "$p" ] && r=1
        done
        printf '%s' "$r"
      })
    fi
    if [ "$has" = 0 ]; then
      if [ -d "$home" ] && [ ! -x "$home" ]; then
        printf '#X %s\tunreadable\n' "$home/.ssh"
      fi
      continue
    fi
    cnt=$((cnt + 1))
    if [ "$cnt" -gt 2000 ]; then
      printf '#X accounts\tlimit of 2000 accounts reached\n'
      break
    fi
    val user "$u"
    d="$home/.ssh"
    ASU=0
    if [ "$ROOT" = 1 ]; then
      num=1
      case "$uid" in
        '' | *[!0-9]*) num=0 ;;
      esac
      case "$gid" in
        '' | *[!0-9]*) num=0 ;;
      esac
      if [ "$num" = 0 ]; then
        printf '#X %s\tuid or gid not numeric\n' "$d"
        continue
      fi
      if [ "$uid" != 0 ]; then
        # fail closed: without setpriv nothing in this home is read (reading as root would
        # bring back the symlink race)
        if [ "$SETPRIV" != yes ]; then
          printf '#X %s\tnot read: setpriv missing\n' "$d"
          continue
        fi
        ASU=1
      fi
    fi
    if [ -L "$d" ]; then
      # a user controls ~/.ssh: never follow a link (it could point at /root/.ssh or /etc)
      fhdr "$d" "$u"
      printf '#X %s\tsymlink not followed\n' "$d"
    elif [ -d "$d" ]; then
      fhdr "$d" "$u"
      if utest -r "$d" && utest -x "$d"; then
        uls "$d" 2>/dev/null | head -n 101 | {
          n=0
          while IFS= read -r e; do
            [ -n "$e" ] || continue
            n=$((n + 1))
            if [ "$n" -gt 100 ]; then
              printf '#X %s\tmore than 100 entries\n' "$d"
              break
            fi
            p="$d/$e"
            case "$e" in
              *"$T"*)
                printf '#X %s\tname with tab or newline skipped\n' "$d"
                continue
                ;;
            esac
            if [ ! -e "$p" ] && [ ! -L "$p" ]; then
              printf '#X %s\tname with tab or newline skipped\n' "$d"
              continue
            fi
            case "$NL$akfs" in
              *"$NL$p$NL"*) continue ;;
            esac
            fhdr "$p" "$u"
            if [ -L "$p" ]; then
              printf '#X %s\tsymlink not followed\n' "$p"
              continue
            fi
            [ -f "$p" ] || continue
            case "$e" in
              known_hosts* | config | *.pub) content "$p" ;;
              *) privkey "$p" ;;
            esac
          done
        }
      else
        printf '#X %s\t%s\n' "$d" "$(unr)"
      fi
    fi
    printf '%s' "$akfs" | while IFS= read -r p; do
      [ -n "$p" ] || continue
      val akf "$p"
      if [ -L "$p" ] || [ -L "${p%/*}" ]; then
        fhdr "$p" "$u"
        printf '#X %s\tsymlink not followed\n' "$p"
      elif [ -f "$p" ]; then
        fhdr "$p" "$u"
        content "$p"
      elif [ -e "$p" ]; then
        fhdr "$p" "$u"
      fi
    done
  done
}

# ---------------------------------------------------------------- SYSTEM
sec SYSTEM
ASU=0
for f in /etc/ssh/ssh_known_hosts /etc/ssh/ssh_config; do
  [ -f "$f" ] || continue
  fhdr "$f" ""
  content "$f"
done
n=0
for f in /etc/ssh/ssh_config.d/*; do
  [ -f "$f" ] || continue
  n=$((n + 1))
  [ "$n" -le 20 ] || break
  fhdr "$f" ""
  content "$f"
done

sec END
printf '#END %s\n' "$NSEC"
