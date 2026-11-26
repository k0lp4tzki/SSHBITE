. /lab/image/lib.sh
mkuser app; sshdir app
mkuser monitor; sshdir monitor
sshdir root
put /home/app/.ssh/authorized_keys app 600
put /home/app/.ssh/config app 644
privkey k_mon /home/monitor/.ssh/id_ecdsa monitor 600
put /etc/ssh/ssh_known_hosts root 644
put /root/.ssh/authorized_keys root 600
