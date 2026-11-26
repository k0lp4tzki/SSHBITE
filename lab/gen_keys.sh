#!/bin/sh
# Generates every key of the lab ONCE. The output under lab/keys/ is committed so that
# fingerprints are fixed (spec 9.2). Do not run this again unless you mean to change
# all fingerprints; lab/expected.yaml and tests/e2e depend on them only through the
# files, so re-running is safe but produces a different lab.
# Needs: ssh-keygen from OpenSSH <= 9.7 (DSA generation), python3 (seed rendering).
set -eu
cd "$(dirname "$0")"
K=keys
mkdir -p "$K"
gen() { # gen NAME TYPE BITS COMMENT [PASSPHRASE]
  rm -f "$K/$1" "$K/$1.pub"
  if [ -n "$3" ]; then b="-b $3"; else b=""; fi
  # shellcheck disable=SC2086
  ssh-keygen -q -t "$2" $b -C "$4" -N "${5:-}" -f "$K/$1"
}

# SSHBITE's own audit key and the lab control key (test harness only, never scanned)
gen audit_ed25519 ed25519 "" "sshbite-audit"
gen labctl_ed25519 ed25519 "" "lab-control"
gen labctl_host_ed25519 ed25519 "" "lab-control-host"

# host keys
# r1 (AlmaLinux 9, stand-alone) came later: its keys were added with the same names, types and comments
for h in jump a1 a2 a3 a4 a5 b1 b2 b3 b4 b5 c1 c2 r1; do
  gen "${h}_host_ed25519" ed25519 "" "root@$h"
  gen "${h}_host_ecdsa" ecdsa 256 "root@$h"
done
gen b3_old_host_ed25519 ed25519 "" "root@b3-old"
gen c2_rotated_host_ed25519 ed25519 "" "root@c2"
gen c2_rotated_host_ecdsa ecdsa 256 "root@c2"

# user keys (comment = label, spec 9.2)
gen k_ops ed25519 "" "ops@jump" labpass
gen k_fleet rsa 3072 "fleet-deploy"
gen k_deploy rsa 2048 "deploy@a1"
gen k_dsa dsa 1024 "legacy-dsa"
gen k_backup rsa 1024 "old-backup"
gen k_mon ecdsa 256 "monitor@a3"
gen k_bridge ed25519 "" "ops2@b3"
gen k_dup rsa 4096 "shared-team"
gen k_orphan ed25519 "" "contractor-2019"
gen k_ca ed25519 "" "ops-ca"
gen k_carol ed25519 "" "carol@b5"
gen k_new ed25519 "" "new-unknown"
gen k_alice ed25519 "" "alice@r1"
# random keys for known_hosts lines that point at nothing real
gen random_1 ed25519 "" "random-1"
gen random_2 ed25519 "" "random-2"
gen random_3 ed25519 "" "random-3"
chmod 600 "$K"/*
chmod 644 "$K"/*.pub
python3 render_seed.py
