. /lab/image/lib.sh
sshdir root
put /root/.ssh/authorized_keys root 600
# sudo needs the account's password here
printf 'sshbite ALL=(root) ALL\n' > /etc/sudoers.d/sshbite
chmod 440 /etc/sudoers.d/sshbite
echo 'sshbite:labsudo' | chpasswd
