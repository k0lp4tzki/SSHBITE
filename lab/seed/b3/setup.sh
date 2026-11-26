. /lab/image/lib.sh
mkuser ops2; sshdir ops2; sshdir root
put /home/ops2/.ssh/config ops2 644
put /home/ops2/.ssh/known_hosts ops2 644
privkey k_bridge /home/ops2/.ssh/id_ed25519 ops2 600
put /root/.ssh/authorized_keys root 600
