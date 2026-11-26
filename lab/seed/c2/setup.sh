. /lab/image/lib.sh
mkuser svc; sshdir svc; sshdir root
put /home/svc/.ssh/authorized_keys svc 600
put /root/.ssh/authorized_keys root 600
