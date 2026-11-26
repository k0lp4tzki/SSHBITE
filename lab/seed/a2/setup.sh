. /lab/image/lib.sh
sshd_lab yes no
mkuser deploy; sshdir deploy; sshdir root
put /home/deploy/.ssh/authorized_keys deploy 600
put /home/deploy/.ssh/config deploy 644
put /home/deploy/.ssh/known_hosts deploy 644
# 'backup' is Debian's system account: home /var/backups, shell /usr/sbin/nologin
sshdir backup
put /var/backups/.ssh/authorized_keys backup 600
put /root/.ssh/authorized_keys root 600
