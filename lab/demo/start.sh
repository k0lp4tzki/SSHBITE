#!/bin/sh
# Lab demo only (compose.lab.yaml): the real SSHBITE image, run against the test lab.
# It does what docs/install.md asks an admin to do by hand, then starts the UI:
#   config validate --connect, user add, one scan, sshbite serve.
# Do not use this script or its keys (lab/keys/) for real systems.
#
# UI login: user "admin" with the password from SSHBITE_DEMO_PASSWORD. Without it, a random password is
# generated and printed ONCE to the container log, when the user is created. The old fixed demo password
# is refused.
set -eu
echo "== id"
id
echo "== sshbite --version"
sshbite --version
echo "== installed Python packages (runtime image: requirements-runtime.lock, no test tools)"
python -m pip list --disable-pip-version-check 2>/dev/null || true

pw=${SSHBITE_DEMO_PASSWORD:-}
if [ "$pw" = "sshbite-lab-demo" ]; then
  echo "refusing to start: SSHBITE_DEMO_PASSWORD is the old published demo password 'sshbite-lab-demo'." >&2
  echo "Unset it (a random password is generated) or choose your own of at least 12 characters." >&2
  exit 1
fi
generated=0
if [ -z "$pw" ]; then
  pw=$(python -c 'import secrets; print(secrets.token_urlsafe(18))')   # 24 characters, 144 random bits
  generated=1
fi

# git checks the lab key out as 0644; SSHBITE refuses an audit key that is not 0600, so copy it.
install -m 600 /lab-keys/audit_ed25519 /data/lab_audit_ed25519

echo "== sshbite config validate --connect"
i=0
until sshbite config validate --connect; do
  i=$((i + 1))
  [ "$i" -lt 30 ] || { echo "entry does not answer" >&2; exit 3; }
  sleep 2
done

echo "== sshbite user add admin --password-stdin"
if ! out=$(printf '%s\n' "$pw" | sshbite user add admin --password-stdin 2>&1); then
  case $out in
    *"exists already"*) echo "user admin exists already (its password was printed when it was created)" ;;
    *) echo "$out" >&2; exit 1 ;;
  esac
else
  echo "$out"
  if [ "$generated" = 1 ]; then
    echo "################################################################################"
    echo "## LAB DEMO LOGIN (shown only now):  user admin   password $pw"
    echo "## Test lab only. Set SSHBITE_DEMO_PASSWORD to choose your own."
    echo "################################################################################"
  fi
fi
unset pw SSHBITE_DEMO_PASSWORD

if sshbite scans list 2>/dev/null | grep -q '^ *[0-9]'; then
  echo "== scans present, no new scan"
else
  # the lab's sudo password (lab/seed/a4) - passed through the environment of this one process only
  echo "== SSHBITE_SUDO_PASSWORD=*** sshbite scan --label 'lab demo'"
  SSHBITE_SUDO_PASSWORD=${LAB_SUDO_PASSWORD:-labsudo} sshbite scan --label "lab demo"
fi
sshbite scans list

echo "== sshbite serve"
exec sshbite serve
