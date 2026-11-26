. /lab/image/lib.sh
mkuser carol; sshdir carol
put /home/carol/.ssh/authorized_keys carol 600
# no sudo for the audit account: b5 is scanned unprivileged
rm -f /etc/sudoers.d/sshbite
