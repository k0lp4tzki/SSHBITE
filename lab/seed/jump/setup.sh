. /lab/image/lib.sh
mkuser ops; sshdir ops
put /home/ops/.ssh/config ops 644
put /home/ops/.ssh/known_hosts ops 644
privkey k_ops /home/ops/.ssh/id_ed25519 ops 600 with-pub
privkey k_fleet /home/ops/.ssh/fleet_rsa ops 600
