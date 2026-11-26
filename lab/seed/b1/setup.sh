. /lab/image/lib.sh
mkuser admin; sshdir admin; sshdir root
put /home/admin/.ssh/authorized_keys admin 600
put /home/admin/.ssh/known_hosts admin 644
put /home/admin/.ssh/config admin 644
put /root/.ssh/authorized_keys root 600
