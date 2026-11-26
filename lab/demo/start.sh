#!/bin/sh
# Lab demo only (top-level compose.yaml): the real SSHBITE image, run against the test lab.
# It does what docs/install.md asks an admin to do by hand, then starts the UI:
#   config validate --connect, user add, one scan with --ask-sudo-password, sshbite serve.
# Do not use this script for real systems: it reads a test-only password from the environment.
set -eu
echo "== id"
id
echo "== sshbite --version"
sshbite --version

# git checks the lab key out as 0644; SSHBITE refuses an audit key that is not 0600, so copy it.
install -m 600 /lab-keys/audit_ed25519 /data/lab_audit_ed25519

echo "== sshbite config validate --connect"
i=0
until sshbite config validate --connect; do
  i=$((i + 1))
  [ "$i" -lt 30 ] || { echo "entry does not answer" >&2; exit 3; }
  sleep 2
done

pw=${SSHBITE_DEMO_PASSWORD:-sshbite-lab-demo}
echo "== sshbite user add admin"
if ! out=$(printf '%s\n%s\n' "$pw" "$pw" | sshbite user add admin 2>&1); then
  case $out in
    *"exists already"*) echo "user admin exists already" ;;
    *) echo "$out" >&2; exit 1 ;;
  esac
else
  echo "$out" | grep -v -i warning || true
fi

if sshbite scans list 2>/dev/null | grep -q '^ *[0-9]'; then
  echo "== scans present, no new scan"
else
  echo "== sshbite scan --ask-sudo-password --label 'lab demo'"
  printf '%s\n' "${LAB_SUDO_PASSWORD:-labsudo}" | sshbite scan --ask-sudo-password --label "lab demo"
fi
sshbite scans list

echo "== sshbite serve"
exec sshbite serve
