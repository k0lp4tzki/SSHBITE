. /lab/image/lib.sh
mkuser alice; sshdir alice
mkuser bob; sshdir bob
sshdir root
put /home/alice/.ssh/config alice 644
privkey k_dup /home/alice/.ssh/id_rsa alice 600
privkey k_dup /home/bob/.ssh/id_rsa bob 600
put /root/.ssh/authorized_keys root 600
