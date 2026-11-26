. /lab/image/lib.sh
mkuser deploy; sshdir deploy; sshdir root
put /home/deploy/.ssh/authorized_keys deploy 600
put /home/deploy/.ssh/known_hosts deploy 644
put /home/deploy/.ssh/config deploy 644
privkey k_deploy /home/deploy/.ssh/id_rsa deploy 644
put /root/.ssh/authorized_keys root 600
