. /lab/image/lib.sh
sshd_lab prohibit-password yes
mkuser www; sshdir www
mkuser monitor; sshdir monitor
mkuser alice; sshdir alice
sshdir root
put /home/www/.ssh/known_hosts www 644
put /home/www/.ssh/authorized_keys www 600
privkey k_backup /home/www/.ssh/backup_rsa www 600
put /home/monitor/.ssh/authorized_keys monitor 600
put /home/alice/.ssh/authorized_keys alice 600
put /root/.ssh/authorized_keys root 600
